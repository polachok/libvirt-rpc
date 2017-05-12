use ::xdr_codec;
use xdr_codec::{Pack,Unpack};
use std::marker::PhantomData;
use std::default::Default;


const VIR_UUID_BUFLEN: usize = 16;
const ProcConnectListDefinedDomains: i32 = 21;
const ProcConnectGetLibVersion: i32 = 157;
const ProcAuthList: i32 = 66;
const ProcConnectOpen: i32 = 1;
const ProcDomainCreateWithFlags: i32 = 196;
const ProcDomainUndefineFlags: i32 = 231;
const ProcDomainDefineXMLFlags: i32 = 350;

include!(concat!(env!("OUT_DIR"), "/virnetprotocol_xdr.rs"));

#[derive(Debug)]
pub struct Domain(remote_nonnull_domain);

impl Domain {
    pub fn name(&self) -> String {
        self.0.name.0.clone()
    }

    pub fn uuid(&self) -> ::uuid::Uuid {
        let bytes = self.0.uuid.0;
        ::uuid::Uuid::from_bytes(&bytes).unwrap()
    }
}

#[derive(Debug)]
pub struct LibvirtRequest<P> {
    header: virNetMessageHeader,
    payload: P,
}

impl<P: xdr_codec::Pack<Out>, Out: xdr_codec::Write> Pack<Out> for LibvirtRequest<P> {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        let mut sz: usize = 0;
        sz += try!(self.header.pack(out));
        sz += try!(self.payload.pack(out));
        Ok(sz)
    }
}

/// Auth list request must be the first request
#[derive(Debug)]
pub struct AuthListRequest(LibvirtRequest<()>);

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

        AuthListRequest(LibvirtRequest {
            header: header, 
            payload: (),
        })
    }
}

impl<Out: xdr_codec::Write> Pack<Out> for AuthListRequest {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        self.0.pack(out)
    }
}

/// Connect open request
#[derive(Debug)]
pub struct ConnectOpenRequest(LibvirtRequest<remote_connect_open_args>);

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

        ConnectOpenRequest(LibvirtRequest {
            header: header, 
            payload: payload,
        })
    }
}

impl<Out: xdr_codec::Write> Pack<Out> for ConnectOpenRequest {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        self.0.pack(out)
    }
}

#[derive(Debug)]
pub struct GetLibVersionRequest(LibvirtRequest<()>);

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
        GetLibVersionRequest(LibvirtRequest { header: h, payload: () })
    }
}

impl<Out: xdr_codec::Write> Pack<Out> for GetLibVersionRequest {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        self.0.pack(out)
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
pub struct ListDefinedDomainsRequest(LibvirtRequest<remote_connect_list_defined_domains_args>);

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
        ListDefinedDomainsRequest(LibvirtRequest { header, payload })
    }
}

impl<Out: xdr_codec::Write> Pack<Out> for ListDefinedDomainsRequest {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        self.0.pack(out)
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

#[derive(Debug)]
pub struct DomainDefineXMLRequest(LibvirtRequest<remote_domain_define_xml_flags_args>);

impl DomainDefineXMLRequest {
    pub fn new(serial: u32, xml: &str, flags: u32) -> Self {
        // XXX: use bitflags for flags
        let header = virNetMessageHeader {
            prog: 0x20008086,
            vers: 1,
            proc_: ProcDomainDefineXMLFlags,
            type_: virNetMessageType::VIR_NET_CALL,
            status: virNetMessageStatus::VIR_NET_OK,
            serial: serial,
        };
        let payload = remote_domain_define_xml_flags_args {
            xml: remote_nonnull_string(xml.to_string()),
            flags: flags,
        };
        DomainDefineXMLRequest(LibvirtRequest { header, payload })
    }
}

impl<Out: xdr_codec::Write> Pack<Out> for DomainDefineXMLRequest {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        self.0.pack(out)
    }
}

#[derive(Debug)]
pub struct DomainDefineXMLResponse {
    payload: remote_domain_define_xml_flags_ret,
}

impl DomainDefineXMLResponse {
    pub fn get_domain(&self) -> Domain {
        Domain (self.payload.dom.clone())
    }
}

impl<In: xdr_codec::Read> Unpack<In> for DomainDefineXMLResponse {
    fn unpack(mut input: &mut In) -> xdr_codec::Result<(Self, usize)> {
        let (payload, len) = try!(remote_domain_define_xml_flags_ret::unpack(&mut input));
        Ok((DomainDefineXMLResponse { payload }, len))
    }
}

#[derive(Debug)]
pub struct DomainUndefineRequest(LibvirtRequest<remote_domain_undefine_flags_args>);

impl DomainUndefineRequest {
    pub fn new(serial: u32, domain: Domain, flags: u32) -> Self {
        // XXX: use bitflags for flags
        let header = virNetMessageHeader {
            prog: 0x20008086,
            vers: 1,
            proc_: ProcDomainUndefineFlags,
            type_: virNetMessageType::VIR_NET_CALL,
            status: virNetMessageStatus::VIR_NET_OK,
            serial: serial,
        };

        let payload = remote_domain_undefine_flags_args {
            dom: domain.0,
            flags: flags,
        };
        DomainUndefineRequest(LibvirtRequest { header, payload })
    }
}

impl<Out: xdr_codec::Write> Pack<Out> for DomainUndefineRequest {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        self.0.pack(out)
    }
}

#[derive(Debug)]
pub struct DomainCreateRequest(LibvirtRequest<remote_domain_create_with_flags_args>);

impl DomainCreateRequest {
    pub fn new(serial: u32, domain: Domain, flags: u32) -> Self {
        // XXX: use bitflags for flags
        let header = virNetMessageHeader {
            prog: 0x20008086,
            vers: 1,
            proc_: ProcDomainCreateWithFlags,
            type_: virNetMessageType::VIR_NET_CALL,
            status: virNetMessageStatus::VIR_NET_OK,
            serial: serial,
        };

        let payload = remote_domain_create_with_flags_args {
            dom: domain.0,
            flags: flags,
        };
        DomainCreateRequest(LibvirtRequest { header, payload })
    }
}

impl<Out: xdr_codec::Write> Pack<Out> for DomainCreateRequest {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        self.0.pack(out)
    }
}


#[derive(Debug)]
pub struct DomainCreateResponse {
    payload: remote_domain_create_with_flags_ret,
}

impl<In: xdr_codec::Read> Unpack<In> for DomainCreateResponse {
    fn unpack(mut input: &mut In) -> xdr_codec::Result<(Self, usize)> {
        let (payload, len) = try!(remote_domain_create_with_flags_ret::unpack(&mut input));
        Ok((DomainCreateResponse { payload }, len))
    }
}

impl DomainCreateResponse {
    pub fn get_domain(&self) -> Domain {
        Domain (self.payload.dom.clone())
    }
}
