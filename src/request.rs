use ::xdr_codec;
use xdr_codec::{Pack,Unpack};
use std::convert::From;
use std::default::Default;

pub mod generated {
    #![allow(non_camel_case_types)]
    #![allow(dead_code)]
    #![allow(non_snake_case)]
    #![allow(unused_assignments)]
    use ::xdr_codec;
    use xdr_codec::{Pack,Unpack};

    include!(concat!(env!("OUT_DIR"), "/virnetprotocol_xdr.rs"));
    include!(concat!(env!("OUT_DIR"), "/remote_protocol_xdr.rs"));
}

pub use self::generated::remote_procedure;
pub use self::generated::{virNetMessageStatus,virNetMessageHeader,virNetMessageError};

#[derive(Debug)]
pub struct Domain(generated::remote_nonnull_domain);

impl Domain {
    pub fn name(&self) -> String {
        self.0.name.0.clone()
    }

    pub fn uuid(&self) -> ::uuid::Uuid {
        let bytes = self.0.uuid.0;
        ::uuid::Uuid::from_bytes(&bytes).unwrap()
    }
}

impl ::std::default::Default for generated::virNetMessageHeader {
    fn default() -> Self {
        generated::virNetMessageHeader {
            prog: 0x20008086,
            vers: 1,
            proc_: 0,
            type_: generated::virNetMessageType::VIR_NET_CALL,
            serial: 0,
            status: generated::virNetMessageStatus::VIR_NET_OK,
        }
    }
}

#[derive(Debug)]
pub struct LibvirtMessage<P> {
    pub header: generated::virNetMessageHeader,
    pub payload: P,
}

impl<P: xdr_codec::Pack<Out>, Out: xdr_codec::Write> Pack<Out> for LibvirtMessage<P> {
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
pub struct AuthListRequest(());

impl AuthListRequest {
    pub fn new() -> Self {
        AuthListRequest(())
    }
}

delegate_pack_impl!(AuthListRequest);

#[derive(Debug)]
pub struct AuthListResponse(LibvirtResponse<generated::remote_auth_list_ret>);
delegate_unpack_impl!(AuthListResponse);

/// Connect open request
#[derive(Debug)]
pub struct ConnectOpenRequest(generated::remote_connect_open_args);

impl ConnectOpenRequest {
    pub fn new() -> Self {
        let payload = generated::remote_connect_open_args {
            name: Some(generated::remote_nonnull_string("qemu:///system".to_string())),
            flags: 0,
        };

        ConnectOpenRequest(payload)
    }
}

delegate_pack_impl!(ConnectOpenRequest);

#[derive(Debug)]
pub struct ConnectOpenResponse(LibvirtResponse<()>);
delegate_unpack_impl!(ConnectOpenResponse);

#[derive(Debug)]
pub struct GetLibVersionRequest(());

impl GetLibVersionRequest {
    pub fn new() -> Self {
        GetLibVersionRequest(())
    }
}

delegate_pack_impl!(GetLibVersionRequest);

#[derive(Debug)]
pub struct GetLibVersionResponse(LibvirtResponse<generated::remote_connect_get_lib_version_ret>);

impl GetLibVersionResponse {
    pub fn version(&self) -> (u32, u32, u32) {
        let mut version = (self.0).0.lib_ver;

        let major = version / 1000000;
        version %= 1000000;
        let minor = version / 1000;
        version %= 1000;
        let micro = version;

        (major as u32, minor as u32, micro as u32)
    }
}

delegate_unpack_impl!(GetLibVersionResponse);

#[derive(Debug)]
pub struct ListDefinedDomainsRequest(generated::remote_connect_list_defined_domains_args);

impl ListDefinedDomainsRequest {
    pub fn new() -> Self {
        let payload = generated::remote_connect_list_defined_domains_args {
            maxnames: generated::REMOTE_DOMAIN_LIST_MAX as i32,
        };
        ListDefinedDomainsRequest(payload)
    }
}

delegate_pack_impl!(ListDefinedDomainsRequest);

#[derive(Debug)]
pub struct ListDefinedDomainsResponse(LibvirtResponse<generated::remote_connect_list_defined_domains_ret>);

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
pub struct DomainDefineXMLRequest(generated::remote_domain_define_xml_flags_args);

impl DomainDefineXMLRequest {
    pub fn new(xml: &str, flags: u32) -> Self {
        // XXX: use bitflags for flags
        let header = generated::virNetMessageHeader {
            proc_: remote_procedure::REMOTE_PROC_DOMAIN_DEFINE_XML_FLAGS as i32,
            ..Default::default()
        };
        let payload = generated::remote_domain_define_xml_flags_args {
            xml: generated::remote_nonnull_string(xml.to_string()),
            flags: flags,
        };
        DomainDefineXMLRequest(payload)
    }
}

delegate_pack_impl!(DomainDefineXMLRequest);

#[derive(Debug)]
pub struct DomainDefineXMLResponse(LibvirtResponse<generated::remote_domain_define_xml_flags_ret>);

impl DomainDefineXMLResponse {
    pub fn get_domain(&self) -> Domain {
        Domain ((self.0).0.dom.clone())
    }
}

delegate_unpack_impl!(DomainDefineXMLResponse);

#[derive(Debug)]
pub struct DomainUndefineRequest(generated::remote_domain_undefine_flags_args);

impl DomainUndefineRequest {
    pub fn new(domain: Domain, flags: u32) -> Self {
        // XXX: use bitflags for flags
        let header = generated::virNetMessageHeader {
            proc_: remote_procedure::REMOTE_PROC_DOMAIN_UNDEFINE_FLAGS as i32,
            ..Default::default()
        };

        let payload = generated::remote_domain_undefine_flags_args {
            dom: domain.0,
            flags: flags,
        };
        DomainUndefineRequest(payload)
    }
}

delegate_pack_impl!(DomainUndefineRequest);

#[derive(Debug)]
pub struct DomainUndefineResponse(LibvirtResponse<()>);
delegate_unpack_impl!(DomainUndefineResponse);

bitflags! {
    pub flags DomainCreateFlags: u32 {
        const VIR_DOMAIN_START_PAUSED = 1,
        const VIR_DOMAIN_START_AUTODESTROY = 2,
        const VIR_DOMAIN_START_BYPASS_CACHE = 4,
        const VIR_DOMAIN_START_FORCE_BOOT = 8,
        const VIR_DOMAIN_START_VALIDATE = 16,
    }
}

#[derive(Debug)]
pub struct DomainCreateRequest(generated::remote_domain_create_with_flags_args);

impl DomainCreateRequest {
    pub fn new(domain: Domain, flags: DomainCreateFlags) -> Self {
        let payload = generated::remote_domain_create_with_flags_args {
            dom: domain.0,
            flags: flags.bits(),
        };
        DomainCreateRequest(payload)
    }
}

delegate_pack_impl!(DomainCreateRequest);

#[derive(Debug)]
pub struct DomainCreateResponse(LibvirtResponse<generated::remote_domain_create_with_flags_ret>);

delegate_unpack_impl!(DomainCreateResponse);

impl DomainCreateResponse {
    pub fn get_domain(&self) -> Domain {
        Domain ((self.0).0.dom.clone())
    }
}


#[derive(Debug)]
pub struct ListAllDomainsRequest(generated::remote_connect_list_all_domains_args);

impl ListAllDomainsRequest {
    pub fn new(flags: u32) -> Self {
        let payload = generated::remote_connect_list_all_domains_args {
            need_results: 1,
            flags: flags,
        };
        ListAllDomainsRequest(payload)
    }
}

delegate_pack_impl!(ListAllDomainsRequest);

#[derive(Debug)]
pub struct ListAllDomainsResponse(generated::remote_connect_list_all_domains_ret);

impl ListAllDomainsResponse {
    pub fn get_domains(&self) -> Vec<Domain> {
        let mut domains = Vec::new();
        for dom in &(self.0).domains {
            domains.push(Domain(dom.clone()))
        }
        domains
    }
}

delegate_unpack_impl!(ListAllDomainsResponse);

