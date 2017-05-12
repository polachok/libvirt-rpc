extern crate xdr_codec;
extern crate byteorder;
extern crate uuid;

use xdr_codec::record::{XdrRecordWriter,XdrRecordReader};
use xdr_codec::{Pack,Unpack};
use std::io::{BufWriter,BufReader};

use byteorder::NetworkEndian;

mod request;
use request::*;

const VIR_UUID_BUFLEN: usize = 16;
const ProcConnectGetLibVersion: i32 = 157;
const ProcAuthList: i32 = 66;
const ProcConnectOpen: i32 = 1;

use std::os::unix::net::UnixStream;
use std::io::Cursor;

pub struct Libvirt<Io: ::std::io::Read+::std::io::Write> {
    serial: u32,
    stream: Io,
}

#[derive(Debug)]
pub enum LibvirtError {
    XdrError(xdr_codec::Error),
    Libvirt(request::virNetMessageError),
}

impl ::std::convert::From<::std::io::Error> for LibvirtError {
    fn from(e: ::std::io::Error) -> Self {
        LibvirtError::XdrError(e.into())
    }
}

impl ::std::convert::From<xdr_codec::Error> for LibvirtError {
    fn from(e: xdr_codec::Error) -> Self {
        LibvirtError::XdrError(e)
    }
}

impl ::std::convert::From<virNetMessageError> for LibvirtError {
    fn from(e: virNetMessageError) -> Self {
        LibvirtError::Libvirt(e)
    }
}

impl ::std::fmt::Display for LibvirtError {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> std::fmt::Result {
        match self {
           &LibvirtError::XdrError(ref e) => e.fmt(f),
           &LibvirtError::Libvirt(ref vmsg) => vmsg.fmt(f),
        }
    }
}

impl ::std::error::Error for LibvirtError {
    fn description(&self) -> &str {
        match self {
            &LibvirtError::XdrError(ref e) => e.description(),
            &LibvirtError::Libvirt(ref vmsg) => vmsg.description(),
        }
    }

}

impl ::std::fmt::Display for virNetMessageError {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> std::fmt::Result {
        match self.message {
            Some(ref msg) => write!(f, "{}", &msg.0),
            None => write!(f, "{:?}", self.message),
        }
    }
}

impl ::std::error::Error for virNetMessageError {
    fn description(&self) -> &str {
        match self.message {
            Some(ref msg) => &msg.0,
            None => panic!("virNetMessageError message absent"),
        }
    }
}

impl<Io> Libvirt<Io> where Io: ::std::io::Read+::std::io::Write {
    pub fn new(stream: Io) -> Self {
        Libvirt {
            serial: 0,
            stream: stream,
        }
    }

    fn serial(&mut self) -> u32 {
        let serial = self.serial;
        self.serial += 1;
        return serial;
    }

    fn write_packet<P: xdr_codec::Pack<Cursor<Vec<u8>>>>(&mut self, packet: P) -> xdr_codec::Result<usize> {
        use std::io::Cursor;
        use byteorder::WriteBytesExt;

        let mut buf = Vec::new();
        let (sz, buf) = {
            let mut c = Cursor::new(buf);
            let sz = try!(packet.pack(&mut c));
            let inner = c.into_inner();
            (sz, inner)
        };
        let len = sz + 4;
        self.stream.write_u32::<NetworkEndian>(len as u32);
        self.stream.write(&buf[0..sz]);
        //println!("LEN = {:?}\n", len);
        Ok(len as usize)
    }

    fn read_packet_raw(&mut self) -> Result<Vec<u8>, LibvirtError> {
        use byteorder::ReadBytesExt;

        let mut len = try!(self.stream.read_u32::<NetworkEndian>());
        //println!("TOTAL LENGTH {}", len);
        len -= 4; // skip len

        let mut buf = vec![0;len as usize];
        try!(self.stream.read_exact(&mut buf[0..len as usize]));
        let mut cur = Cursor::new(buf);

        let (header, hlen) = try!(virNetMessageHeader::unpack(&mut cur));
       
        if header.status == virNetMessageStatus::VIR_NET_OK {
            let buf = cur.into_inner();
            return Ok(buf);
        }

        let (err, _) = try!(virNetMessageError::unpack(&mut cur));
        return Err(LibvirtError::from(err));
    }

    fn read_packet_reply<P: xdr_codec::Unpack<Cursor<Vec<u8>>>>(&mut self) -> Result<P, LibvirtError> {
        use byteorder::{ReadBytesExt};

        let mut len = try!(self.stream.read_u32::<NetworkEndian>());
        len -= 4; // skip len

        // read whole packet
        let mut buf = vec![0;len as usize];
        try!(self.stream.read_exact(&mut buf[0..len as usize]));
        let mut cur = Cursor::new(buf);

        let (header, hlen) = try!(virNetMessageHeader::unpack(&mut cur));
       
        if header.status == virNetMessageStatus::VIR_NET_OK {
            let (pkt, _) = try!(P::unpack(&mut cur));
            return Ok(pkt);
        }

        let (err, _) = try!(virNetMessageError::unpack(&mut cur));
        return Err(LibvirtError::from(err));
    }

    pub fn auth(&mut self) -> Result<(), LibvirtError> {
        let req = AuthListRequest::new(self.serial());

        try!(self.write_packet(req));
        try!(self.read_packet_raw());

        return Ok(());
    }

    pub fn open(&mut self) -> Result<(), LibvirtError> {
        let req = ConnectOpenRequest::new(self.serial());

        try!(self.write_packet(req));
        try!(self.read_packet_raw());

        return Ok(());
    }

    pub fn version(&mut self) -> Result<(u32, u32, u32), LibvirtError> {
        let req = GetLibVersionRequest::new(self.serial());

        try!(self.write_packet(req));
        let pkt: GetLibVersionResponse = try!(self.read_packet_reply());

        let mut version = pkt.version;
        let major = version / 1000000;
        version %= 1000000;
        let minor = version / 1000;
        version %= 1000;
        let micro = version;

        Ok((major as u32, minor as u32, micro as u32))
    }

    pub fn list_defined_domains(&mut self) -> Result<Vec<String>, LibvirtError> {
        let req = ListDefinedDomainsRequest::new(self.serial());

        try!(self.write_packet(req));
        let pkt: ListDefinedDomainsResponse = try!(self.read_packet_reply());
        let names = pkt.get_domain_names();
        Ok(names)
    }

    pub fn define(&mut self, xml: &str) -> Result<Domain, LibvirtError> {
        let req = DomainDefineXMLRequest::new(self.serial(), xml, 1);

        try!(self.write_packet(req));
        let pkt: DomainDefineXMLResponse = try!(self.read_packet_reply());
        let dom = pkt.get_domain();
        Ok(dom)
    }

    pub fn undefine(&mut self, dom: Domain) -> Result<(), LibvirtError> {
        let req = DomainUndefineRequest::new(self.serial(), dom, 0);

        try!(self.write_packet(req));
        let pkt: () = try!(self.read_packet_reply());
        Ok(pkt)
    }

    pub fn start(&mut self, dom: Domain) -> Result<Domain, LibvirtError> {
        let req = DomainCreateRequest::new(self.serial(), dom, 0);

        try!(self.write_packet(req));
        let pkt: DomainCreateResponse = try!(self.read_packet_reply());
        let dom = pkt.get_domain();
        Ok(dom)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_it_doesnt() {
        use std::fs::File;
        use super::Libvirt;
        use std::os::unix::net::UnixStream;
        use std::io::Read;
        let mut stream = UnixStream::connect("/var/run/libvirt/libvirt-sock").unwrap();
        let mut libvirt = Libvirt::new(stream);
        libvirt.auth().unwrap();
        libvirt.open().unwrap();
        let (major, minor, micro) = libvirt.version().unwrap();
        println!("version: {}.{}.{}", major, minor, micro);
        let names = libvirt.list_defined_domains();
        println!("domains: {:?}", names);
        let mut f = File::open("test.xml").unwrap();
        let mut xml = String::new();
        f.read_to_string(&mut xml).unwrap();
        let dom = libvirt.define(&xml).unwrap();
        println!("new domain: name: {:?} uuid: {:?}", dom.name(), dom.uuid());
        let names = libvirt.list_defined_domains();
        println!("domains: {:?}", names);
        let dom = libvirt.start(dom).unwrap();
        //libvirt.undefine(dom).unwrap();
        let names = libvirt.list_defined_domains();
        println!("domains: {:?}", names);
    }
    /*
    #[test]
    fn it_works() {
        use std::os::unix::net::UnixStream;
        let mut stream = UnixStream::connect("/var/run/libvirt/libvirt-sock").unwrap();
        use super::{auth,version};
        auth(&mut stream);
        version(&mut stream);
    }
    */
}
