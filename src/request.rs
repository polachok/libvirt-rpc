use ::xdr_codec;
use xdr_codec::{Pack,Unpack};

const VIR_UUID_BUFLEN: usize = 16;
const ProcConnectListDefinedDomains: i32 = 21;
const ProcConnectGetLibVersion: i32 = 157;
const ProcAuthList: i32 = 66;
const ProcConnectOpen: i32 = 1;

include!(concat!(env!("OUT_DIR"), "/virnetprotocol_xdr.rs"));

/// Auth list request must be the first request
#[derive(Debug)]
pub struct AuthListRequest {
    header: virNetMessageHeader,
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

        AuthListRequest {
            header: header, 
        }
    }
}

impl<Out: xdr_codec::Write> Pack<Out> for AuthListRequest {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        self.header.pack(out)
    }
}

/// Connect open request
#[derive(Debug)]
pub struct ConnectOpenRequest {
    header: virNetMessageHeader,
    payload: remote_connect_open_args,
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

        let payload = remote_connect_open_args {
            name: Some(remote_nonnull_string("qemu:///system".to_string())),
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
#[derive(Debug)]
pub struct ListDefinedDomainsRequest {
    header: virNetMessageHeader,
    payload: remote_connect_list_defined_domains_args,
}

impl ListDefinedDomainsRequest {
    pub fn new(serial: u32) -> Self {
        let header = virNetMessageHeader {
            prog: 0x20008086,
            vers: 1,
            proc_: ProcConnectListDefinedDomains,
            type_: virNetMessageType::VIR_NET_CALL,
            status: virNetMessageStatus::VIR_NET_OK,
            serial: serial,
        };
        let payload = remote_connect_list_defined_domains_args {
            maxnames: REMOTE_DOMAIN_LIST_MAX as i32,
        };
        ListDefinedDomainsRequest { header, payload }
    }
}

impl<Out: xdr_codec::Write> Pack<Out> for ListDefinedDomainsRequest {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        let mut sz: usize = 0;
        sz += try!(self.header.pack(out));
        sz += try!(self.payload.pack(out));
        Ok(sz)
    }
}

#[derive(Debug)]
pub struct ListDefinedDomainsResponse {
    payload: remote_connect_list_defined_domains_ret,
}

impl ListDefinedDomainsResponse {
    pub fn get_domain_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        for name in &self.payload.names {
            names.push(name.0.to_string());
        }
        names
    }
}

impl<In: xdr_codec::Read> Unpack<In> for ListDefinedDomainsResponse {
    fn unpack(mut input: &mut In) -> xdr_codec::Result<(Self, usize)> {
        let (v, len) = try!(remote_connect_list_defined_domains_ret::unpack(&mut input));
        Ok((ListDefinedDomainsResponse { payload: v }, len))
    }
}
