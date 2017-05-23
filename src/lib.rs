extern crate xdr_codec;
extern crate byteorder;
extern crate uuid;
extern crate tokio_io;
extern crate tokio_proto;
extern crate tokio_service;
extern crate tokio_core;
extern crate tokio_uds;
extern crate tokio_uds_proto;
extern crate bytes;
#[macro_use]
extern crate futures;
#[macro_use]
extern crate log;
extern crate env_logger;
#[macro_use]
extern crate bitflags;

use xdr_codec::{Pack,Unpack};

use byteorder::NetworkEndian;

pub mod request;
pub mod async;
use request::*;

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

        let buf = Vec::new();
        let (sz, buf) = {
            let mut c = Cursor::new(buf);
            let sz = try!(packet.pack(&mut c));
            let inner = c.into_inner();
            (sz, inner)
        };
        let len = sz + 4;
        try!(self.stream.write_u32::<NetworkEndian>(len as u32));
        try!(self.stream.write(&buf[0..sz]));
        //println!("LEN = {:?}\n", len);
        Ok(len as usize)
    }

    /*
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
    */

    fn read_packet_reply<P: xdr_codec::Unpack<Cursor<Vec<u8>>>>(&mut self) -> Result<P, LibvirtError> {
        use byteorder::{ReadBytesExt};

        let mut len = try!(self.stream.read_u32::<NetworkEndian>());
        len -= 4; // skip len

        // read whole packet
        let mut buf = vec![0;len as usize];
        try!(self.stream.read_exact(&mut buf[0..len as usize]));
        let mut cur = Cursor::new(buf);

        let (header, _) = try!(virNetMessageHeader::unpack(&mut cur));
       
        if header.status == virNetMessageStatus::VIR_NET_OK {
            let (pkt, _) = try!(P::unpack(&mut cur));
            return Ok(pkt);
        }

        let (err, _) = try!(virNetMessageError::unpack(&mut cur));
        return Err(LibvirtError::from(err));
    }

    fn request<Req: xdr_codec::Pack<Cursor<Vec<u8>>>, Resp: xdr_codec::Unpack<Cursor<Vec<u8>>>>(&mut self, packet: Req) -> Result<Resp, LibvirtError> {
        try!(self.write_packet(packet));
        self.read_packet_reply()
    }

    fn make_request<T>(&mut self, procedure: request::remote_procedure, payload: T) -> request::LibvirtMessage<T> {
        use std::default::Default;
        let serial = self.serial();

        LibvirtMessage {
            header: request::virNetMessageHeader {
                serial: serial,
                proc_: procedure as i32,
                ..Default::default()
            },
            payload: payload,
        }
    }

    pub fn auth(&mut self) -> Result<AuthListResponse, LibvirtError> {
        use request::remote_procedure::*;
        let req = self.make_request(REMOTE_PROC_AUTH_LIST, AuthListRequest::new());
        self.request(req)
    }

    pub fn open(&mut self) -> Result<ConnectOpenResponse, LibvirtError> {
        use request::remote_procedure::*;
        let req = self.make_request(REMOTE_PROC_CONNECT_OPEN, ConnectOpenRequest::new());
        self.request(req)
    }

    pub fn version(&mut self) -> Result<(u32, u32, u32), LibvirtError> {
        use request::remote_procedure::*;
        let req = self.make_request(REMOTE_PROC_CONNECT_GET_LIB_VERSION, GetLibVersionRequest::new());

        let pkt: GetLibVersionResponse = try!(self.request(req));

        Ok(pkt.version())
    }

    pub fn list_defined_domains(&mut self) -> Result<Vec<String>, LibvirtError> {
        use request::remote_procedure::*;
        let req = self.make_request(REMOTE_PROC_CONNECT_LIST_DEFINED_DOMAINS, ListDefinedDomainsRequest::new());

        let pkt: ListDefinedDomainsResponse = try!(self.request(req));
        let names = pkt.get_domain_names();
        Ok(names)
    }

    pub fn define(&mut self, xml: &str) -> Result<Domain, LibvirtError> {
        use request::remote_procedure::*;
        let req = self.make_request(REMOTE_PROC_DOMAIN_DEFINE_XML_FLAGS, DomainDefineXMLRequest::new(xml, 1));

        let pkt: DomainDefineXMLResponse = try!(self.request(req));
        let dom = pkt.get_domain();
        Ok(dom)
    }

    pub fn undefine(&mut self, dom: Domain) -> Result<DomainUndefineResponse, LibvirtError> {
        use request::remote_procedure::*;
        let req = self.make_request(REMOTE_PROC_DOMAIN_UNDEFINE_FLAGS, DomainUndefineRequest::new(dom, 0));

        self.request(req)
    }

    pub fn start(&mut self, dom: Domain) -> Result<Domain, LibvirtError> {
        use request::remote_procedure::*;
        let req = self.make_request(REMOTE_PROC_DOMAIN_CREATE_WITH_FLAGS, DomainCreateRequest::new(dom, DomainCreateFlags::empty()));

        let pkt: DomainCreateResponse = try!(self.request(req));
        let dom = pkt.get_domain();
        Ok(dom)
    }
}
#[cfg(test)]
mod tests {
    /*
    #[test]
    fn no_it_doesnt() {
        use std::fs::File;
        use super::Libvirt;
        use std::os::unix::net::UnixStream;
        use std::io::Read;
        let mut stream = UnixStream::connect("/var/run/libvirt/libvirt-sock").unwrap();
        let mut libvirt = Libvirt::new(stream);
        println!("authorizing");
        libvirt.auth().unwrap();
        println!("opening");
        libvirt.open().unwrap();
        println!("getting version");
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
    */
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