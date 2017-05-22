use ::xdr_codec;
use xdr_codec::{Pack,Unpack};
use std::convert::From;
use std::default::Default;

pub mod generated {
    //! This module is generated from protocol files
    //! It follows original naming convention
    #![allow(non_camel_case_types)]
    #![allow(dead_code)]
    #![allow(non_snake_case)]
    #![allow(unused_assignments)]
    use ::xdr_codec;
    use xdr_codec::{Pack,Unpack};

    include!(concat!(env!("OUT_DIR"), "/virnetprotocol_xdr.rs"));
    include!(concat!(env!("OUT_DIR"), "/remote_protocol_xdr.rs"));
}

pub trait LibvirtRpc<R: ::std::io::Read> where {
    type Response: Send + ::xdr_codec::Unpack<R>;
}

pub use self::generated::remote_procedure;
pub use self::generated::{virNetMessageStatus,virNetMessageHeader,virNetMessageError};

/// VM instance
#[derive(Debug)]
pub struct Domain(generated::remote_nonnull_domain);

impl Domain {
    /// positive integer, unique amongst running guest domains on a single host. An inactive domain does not have an ID.
    pub fn id(&self) -> i32 {
        self.0.id
    }

    /// short string, unique amongst all guest domains on a single host, both running and inactive.
    pub fn name(&self) -> String {
        self.0.name.0.clone()
    }

    /// guaranteed to be unique amongst all guest domains on any host.
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

impl<R: ::std::io::Read> LibvirtRpc<R> for AuthListRequest {
    type Response = AuthListResponse;
}

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

impl<R: ::std::io::Read> LibvirtRpc<R> for ConnectOpenRequest {
    type Response = ConnectOpenResponse;
}

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

impl<R: ::std::io::Read> LibvirtRpc<R> for GetLibVersionRequest {
    type Response = GetLibVersionResponse;
}

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

impl<R: ::std::io::Read> LibvirtRpc<R> for ListDefinedDomainsRequest {
    type Response = ListDefinedDomainsResponse;
}

#[derive(Debug)]
pub struct DomainDefineXMLRequest(generated::remote_domain_define_xml_flags_args);

impl DomainDefineXMLRequest {
    pub fn new(xml: &str, flags: u32) -> Self {
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

impl<R: ::std::io::Read> LibvirtRpc<R> for DomainDefineXMLRequest {
    type Response = DomainDefineXMLResponse;
}

#[derive(Debug)]
pub struct DomainUndefineRequest(generated::remote_domain_undefine_flags_args);

impl DomainUndefineRequest {
    pub fn new(domain: Domain, flags: u32) -> Self {
        // XXX: use bitflags for flags
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

impl<R: ::std::io::Read> LibvirtRpc<R> for DomainUndefineRequest {
    type Response = DomainUndefineResponse;
}

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

impl<R: ::std::io::Read> LibvirtRpc<R> for DomainCreateRequest {
    type Response = DomainCreateResponse;
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

impl<R: ::std::io::Read> LibvirtRpc<R> for ListAllDomainsRequest {
    type Response = ListAllDomainsResponse;
}

#[derive(Debug)]
pub struct DomainEventRegisterAnyRequest(generated::remote_connect_domain_event_register_any_args);

impl DomainEventRegisterAnyRequest {
    pub fn new(event: i32) -> Self {
        let payload = generated::remote_connect_domain_event_register_any_args {
            eventID: event,
        };
        DomainEventRegisterAnyRequest(payload)
    }
}

delegate_pack_impl!(DomainEventRegisterAnyRequest);

#[derive(Debug)]
pub struct DomainEventRegisterAnyResponse(());
delegate_unpack_impl!(DomainEventRegisterAnyResponse);

impl<R: ::std::io::Read> LibvirtRpc<R> for DomainEventRegisterAnyRequest {
    type Response = DomainEventRegisterAnyResponse;
}

#[derive(Debug)]
pub struct DomainEventCallbackRegisterAnyRequest(generated::remote_connect_domain_event_callback_register_any_args);

impl DomainEventCallbackRegisterAnyRequest {
    pub fn new(event: i32, domain: &Domain) -> Self {
        let payload = generated::remote_connect_domain_event_callback_register_any_args {
            eventID: event,
            dom: Some(Box::new(domain.0.clone())),
        };
        DomainEventCallbackRegisterAnyRequest(payload)
    }
}

delegate_pack_impl!(DomainEventCallbackRegisterAnyRequest);

#[derive(Debug)]
pub struct DomainEventCallbackRegisterAnyResponse(generated::remote_connect_domain_event_callback_register_any_ret);

delegate_unpack_impl!(DomainEventCallbackRegisterAnyResponse);

impl DomainEventCallbackRegisterAnyResponse {
    pub fn callback_id(&self) -> i32 {
        self.0.callbackID
    }
}

impl<R: ::std::io::Read> LibvirtRpc<R> for DomainEventCallbackRegisterAnyRequest {
    type Response = DomainEventCallbackRegisterAnyResponse;
}

#[derive(Debug)]
pub struct DomainLookupByUuidRequest(generated::remote_domain_lookup_by_uuid_args);

impl DomainLookupByUuidRequest {
    pub fn new(uuid: &::uuid::Uuid) -> Self {
        let payload = generated::remote_domain_lookup_by_uuid_args {
            uuid: generated::remote_uuid(uuid.as_bytes().clone()),
        };
        DomainLookupByUuidRequest(payload)
    }
}

delegate_pack_impl!(DomainLookupByUuidRequest);

#[derive(Debug)]
pub struct DomainLookupByUuidResponse(generated::remote_domain_lookup_by_uuid_ret);

impl DomainLookupByUuidResponse {
    pub fn domain(&self) -> Domain {
        Domain ((self.0).dom.clone())
    }
}

delegate_unpack_impl!(DomainLookupByUuidResponse);

impl<R: ::std::io::Read> LibvirtRpc<R> for DomainLookupByUuidRequest {
    type Response = DomainLookupByUuidResponse;
}

#[derive(Debug)]
pub enum EventStartedDetailType {
    Booted = 0,
    Migrated = 1,
    Restored = 2,
    FromSnapshot = 3,
    Wakeup = 4,
}

#[derive(Debug)]
pub enum EventStoppedDetailType {
    Shutdown = 0,
    Destroyed = 1,
    Crashed = 2,
    Migrated = 3,
    Saved = 4,
    Failed = 5,
    FromSnapshot = 6,
}

#[derive(Debug)]
pub enum EventResumedDetailType {
    Unpaused = 0,
    Migrated = 1,
    FromSnapshot = 2,
    Postcopy = 3,
}

#[derive(Debug)]
pub enum DomainEventInfo {
    Started(EventStartedDetailType),
    Stopped(EventStoppedDetailType),
    Resumed(EventResumedDetailType),
    Other(i32, i32)
}

#[derive(Debug)]
pub struct DomainEvent {
    domain: Domain,
    info: DomainEventInfo,
}

/* virDomainEventType: http://libvirt.org/html/libvirt-libvirt-domain.html#virDomainEventType */
const VIR_DOMAIN_EVENT_DEFINED: i32	=	0;
const VIR_DOMAIN_EVENT_UNDEFINED: i32	=	1;
const VIR_DOMAIN_EVENT_STARTED: i32	=	2;
const VIR_DOMAIN_EVENT_SUSPENDED: i32	=	3;
const VIR_DOMAIN_EVENT_RESUMED: i32	=	4;
const VIR_DOMAIN_EVENT_STOPPED: i32	=	5;
const VIR_DOMAIN_EVENT_SHUTDOWN: i32	=	6;
const VIR_DOMAIN_EVENT_PMSUSPENDED: i32	=	7;
const VIR_DOMAIN_EVENT_CRASHED: i32	=	8;
const VIR_DOMAIN_EVENT_LAST: i32	=	9;


impl From<generated::remote_domain_event_callback_lifecycle_msg> for DomainEvent {
    fn from(ev: generated::remote_domain_event_callback_lifecycle_msg) -> Self {
        use ::std::mem;
        let info = match ev.msg.event {
            VIR_DOMAIN_EVENT_STARTED => {
                let detail = unsafe { mem::transmute(ev.msg.detail as u8) };
                DomainEventInfo::Started(detail)
            }
            VIR_DOMAIN_EVENT_STOPPED => {
                let detail = unsafe { mem::transmute(ev.msg.detail as u8) };
                DomainEventInfo::Stopped(detail)
            }
            VIR_DOMAIN_EVENT_RESUMED => {
                let detail = unsafe { mem::transmute(ev.msg.detail as u8) };
                DomainEventInfo::Resumed(detail)
            }
            i => {
                DomainEventInfo::Other(i, ev.msg.detail)
            }
        };
        let domain = Domain(ev.msg.dom);
        DomainEvent { domain, info }
    }
}