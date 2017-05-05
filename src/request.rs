use ::xdr_codec;
use xdr_codec::{Pack,Unpack};

const VIR_UUID_BUFLEN: usize = 16;
const ProcConnectGetLibVersion: i32 = 157;
const ProcAuthList: i32 = 66;
const ProcConnectOpen: i32 = 1;

include!(concat!(env!("OUT_DIR"), "/virnetprotocol_xdr.rs"));

#[derive(Debug)]
struct AuthListPayload {
    pub padding: [u8;3],
    pub name: &'static str,
    pub flags: u32,
}

impl<Out: xdr_codec::Write> Pack<Out> for AuthListPayload {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        let mut sz = 0;
        sz += try!(xdr_codec::pack_opaque_array(&self.padding, 3, out));
        sz += try!(self.name.pack(out));
        sz += try!(self.flags.pack(out));
        Ok(sz)
    }
}

/// Auth list request must be the first request
#[derive(Debug)]
pub struct AuthListRequest {
    header: virNetMessageHeader,
    payload: AuthListPayload,
}

impl AuthListRequest {
    pub fn new(serial: u32) -> Self {
        let header = virNetMessageHeader {
            prog: 0x20008086,
            vers: 1,
            proc_: ProcAuthList,
            type_: virNetMessageType::VIR_NET_CALL,
            serial: serial,
            status: virNetMessageStatus::VIR_NET_OK,
        };

        let payload = AuthListPayload {
            padding: [1, 0, 0],
            name: "qemu:///system",
            flags: 0,
        };

        AuthListRequest {
            header: header, 
            payload: payload,
        }
    }
}

impl<Out: xdr_codec::Write> Pack<Out> for AuthListRequest {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        let mut sz = 0;
        sz += try!(self.header.pack(out));
        sz += try!(self.payload.pack(out));
        Ok(sz)
    }
}

/// Connect open request
#[derive(Debug)]
pub struct ConnectOpenRequest {
    header: virNetMessageHeader,
    payload: AuthListPayload,
}

impl ConnectOpenRequest {
    pub fn new(serial: u32) -> Self {
        let header = virNetMessageHeader {
            prog: 0x20008086,
            vers: 1,
            proc_: ProcConnectOpen,
            type_: virNetMessageType::VIR_NET_CALL,
            serial: serial,
            status: virNetMessageStatus::VIR_NET_OK,
        };

        let payload = AuthListPayload {
            padding: [1, 0, 0],
            name: "qemu:///system",
            flags: 0,
        };

        ConnectOpenRequest {
            header: header, 
            payload: payload,
        }
    }
}

impl<Out: xdr_codec::Write> Pack<Out> for ConnectOpenRequest {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        let mut sz = 0;
        sz += try!(self.header.pack(out));
        sz += try!(self.payload.pack(out));
        Ok(sz)
    }
}

#[derive(Debug)]
pub struct GetLibVersionRequest {
    header: virNetMessageHeader,
}

impl GetLibVersionRequest {
    pub fn new(serial: u32) -> Self {
        let h = virNetMessageHeader {
            prog: 0x20008086,
            vers: 1,
            proc_: ProcConnectGetLibVersion,
            type_: virNetMessageType::VIR_NET_CALL,
            status: virNetMessageStatus::VIR_NET_OK,
            serial: serial,
        };
        GetLibVersionRequest { header: h }
    }
}

impl<Out: xdr_codec::Write> Pack<Out> for GetLibVersionRequest {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        self.header.pack(out)
    }
}

#[derive(Debug)]
pub struct GetLibVersionResponse {
    pub version: u64,
}

impl<In: xdr_codec::Read> Unpack<In> for GetLibVersionResponse {
    fn unpack(mut input: &mut In) -> xdr_codec::Result<(Self, usize)> {
        let (v, len2) = try!(u64::unpack(&mut input));
        Ok((GetLibVersionResponse { version: v }, len2))
    }
}
