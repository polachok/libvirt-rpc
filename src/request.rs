use ::xdr_codec;
use xdr_codec::{Pack,Unpack};
use std::convert::From;
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
include!(concat!(env!("OUT_DIR"), "/remote_protocol_xdr.rs"));

// Work around a problem with xdrgen
impl Copy for remote_uuid { }

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

impl ::std::default::Default for virNetMessageHeader {
    fn default() -> Self {
        virNetMessageHeader {
            prog: 0x20008086,
            vers: 1,
            proc_: 0,
            type_: virNetMessageType::VIR_NET_CALL,
            serial: 0,
            status: virNetMessageStatus::VIR_NET_OK,
        }
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

macro_rules! delegate_pack_impl {
    ($t:ty) => {
        impl<Out: xdr_codec::Write> Pack<Out> for $t {
            fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
                self.0.pack(out)
            }
        }
    }
}

#[derive(Debug)]
pub struct LibvirtResponse<P>(P);

impl<P> From<P> for LibvirtResponse<P> {
    fn from(inner: P) -> Self {
        LibvirtResponse(inner)
    }
}

impl<P: xdr_codec::Unpack<In>, In: xdr_codec::Read> Unpack<In> for LibvirtResponse<P> {
    fn unpack(mut input: &mut In) -> xdr_codec::Result<(Self, usize)> {
        let (payload, len) = try!(P::unpack(&mut input));
        Ok((LibvirtResponse(payload), len))
    }
}

macro_rules! delegate_unpack_impl {
    ($t:ty) => {
        impl<In: xdr_codec::Read> Unpack<In> for $t {
            fn unpack(mut input: &mut In) -> xdr_codec::Result<(Self, usize)> {
                let (inner, len) = try!(xdr_codec::Unpack::unpack(input));
                let mut pkt: $t = unsafe { ::std::mem::zeroed() };
                pkt.0 = inner;
                Ok((pkt, len))
                //Ok((From::from(inner), len))
            }
        }

    }
}


/// Auth list request must be the first request
#[derive(Debug)]
pub struct AuthListRequest(LibvirtRequest<()>);

impl AuthListRequest {
    pub fn new(serial: u32) -> Self {
        let header = virNetMessageHeader {
            proc_: ProcAuthList,
            serial: serial,
            ..Default::default()
        };

        AuthListRequest(LibvirtRequest {
            header: header, 
            payload: (),
        })
    }
}

delegate_pack_impl!(AuthListRequest);

#[derive(Debug)]
pub struct AuthListResponse(LibvirtResponse<remote_auth_list_ret>);
delegate_unpack_impl!(AuthListResponse);

/// Connect open request
#[derive(Debug)]
pub struct ConnectOpenRequest(LibvirtRequest<remote_connect_open_args>);

impl ConnectOpenRequest {
    pub fn new(serial: u32) -> Self {
        let header = virNetMessageHeader {
            proc_: ProcConnectOpen,
            serial: serial,
            ..Default::default()
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

delegate_pack_impl!(ConnectOpenRequest);

#[derive(Debug)]
pub struct ConnectOpenResponse(LibvirtResponse<()>);
delegate_unpack_impl!(ConnectOpenResponse);

#[derive(Debug)]
pub struct GetLibVersionRequest(LibvirtRequest<()>);

impl GetLibVersionRequest {
    pub fn new(serial: u32) -> Self {
        let h = virNetMessageHeader {
            proc_: ProcConnectGetLibVersion,
            serial: serial,
            ..Default::default()
        };
        GetLibVersionRequest(LibvirtRequest { header: h, payload: () })
    }
}

delegate_pack_impl!(GetLibVersionRequest);

#[derive(Debug)]
pub struct GetLibVersionResponse(LibvirtResponse<u64>);

impl GetLibVersionResponse {
    pub fn version(&self) -> u64 {
        (self.0).0
    }
}

delegate_unpack_impl!(GetLibVersionResponse);

#[derive(Debug)]
pub struct ListDefinedDomainsRequest(LibvirtRequest<remote_connect_list_defined_domains_args>);

impl ListDefinedDomainsRequest {
    pub fn new(serial: u32) -> Self {
        let header = virNetMessageHeader {
            proc_: ProcConnectListDefinedDomains,
            serial: serial,
            ..Default::default()
        };
        let payload = remote_connect_list_defined_domains_args {
            maxnames: REMOTE_DOMAIN_LIST_MAX as i32,
        };
        ListDefinedDomainsRequest(LibvirtRequest { header, payload })
    }
}

delegate_pack_impl!(ListDefinedDomainsRequest);

#[derive(Debug)]
pub struct ListDefinedDomainsResponse(LibvirtResponse<remote_connect_list_defined_domains_ret>);

impl ListDefinedDomainsResponse {
    pub fn get_domain_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        for name in &(self.0).0.names {
            names.push(name.0.to_string());
        }
        names
    }
}

delegate_unpack_impl!(ListDefinedDomainsResponse);

#[derive(Debug)]
pub struct DomainDefineXMLRequest(LibvirtRequest<remote_domain_define_xml_flags_args>);

impl DomainDefineXMLRequest {
    pub fn new(serial: u32, xml: &str, flags: u32) -> Self {
        // XXX: use bitflags for flags
        let header = virNetMessageHeader {
            proc_: ProcDomainDefineXMLFlags,
            serial: serial,
            ..Default::default()
        };
        let payload = remote_domain_define_xml_flags_args {
            xml: remote_nonnull_string(xml.to_string()),
            flags: flags,
        };
        DomainDefineXMLRequest(LibvirtRequest { header, payload })
    }
}

delegate_pack_impl!(DomainDefineXMLRequest);

#[derive(Debug)]
pub struct DomainDefineXMLResponse(LibvirtResponse<remote_domain_define_xml_flags_ret>);

impl DomainDefineXMLResponse {
    pub fn get_domain(&self) -> Domain {
        Domain ((self.0).0.dom.clone())
    }
}

delegate_unpack_impl!(DomainDefineXMLResponse);

#[derive(Debug)]
pub struct DomainUndefineRequest(LibvirtRequest<remote_domain_undefine_flags_args>);

impl DomainUndefineRequest {
    pub fn new(serial: u32, domain: Domain, flags: u32) -> Self {
        // XXX: use bitflags for flags
        let header = virNetMessageHeader {
            proc_: ProcDomainUndefineFlags,
            serial: serial,
            ..Default::default()
        };

        let payload = remote_domain_undefine_flags_args {
            dom: domain.0,
            flags: flags,
        };
        DomainUndefineRequest(LibvirtRequest { header, payload })
    }
}

delegate_pack_impl!(DomainUndefineRequest);

#[derive(Debug)]
pub struct DomainUndefineResponse(LibvirtResponse<()>);
delegate_unpack_impl!(DomainUndefineResponse);

#[derive(Debug)]
pub struct DomainCreateRequest(LibvirtRequest<remote_domain_create_with_flags_args>);

impl DomainCreateRequest {
    pub fn new(serial: u32, domain: Domain, flags: u32) -> Self {
        // XXX: use bitflags for flags
        let header = virNetMessageHeader {
            proc_: ProcDomainCreateWithFlags,
            serial: serial,
            ..Default::default()
        };

        let payload = remote_domain_create_with_flags_args {
            dom: domain.0,
            flags: flags,
        };
        DomainCreateRequest(LibvirtRequest { header, payload })
    }
}

delegate_pack_impl!(DomainCreateRequest);

#[derive(Debug)]
pub struct DomainCreateResponse(LibvirtResponse<remote_domain_create_with_flags_ret>);

delegate_unpack_impl!(DomainCreateResponse);

impl DomainCreateResponse {
    pub fn get_domain(&self) -> Domain {
        Domain ((self.0).0.dom.clone())
    }
}
