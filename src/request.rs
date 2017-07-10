use ::xdr_codec;
use std::convert::From;

pub mod generated {
    //! This module is generated from protocol files.
    //!
    //! It follows original naming convention
    #![allow(non_camel_case_types)]
    #![allow(dead_code)]
    #![allow(non_snake_case)]
    #![allow(unused_assignments)]
    use ::xdr_codec;
    use super::{ErrorCode,ErrorDomain};

    include!(concat!(env!("OUT_DIR"), "/virnetprotocol_xdr.rs"));
    include!(concat!(env!("OUT_DIR"), "/remote_protocol_xdr.rs"));

    impl virNetMessageError {
        pub fn code(&self) -> ErrorCode {
            ErrorCode::from(self.code)
        }

        pub fn domain(&self) -> ErrorDomain {
            ErrorDomain::from(self.domain)
        }
    }
}

pub trait LibvirtRpc<R: ::std::io::Read> where {
    type Response: Send + ::xdr_codec::Unpack<R>;
}

pub use self::generated::remote_procedure;
pub use self::generated::{virNetMessageStatus,virNetMessageHeader,virNetMessageError};

/// VM instance
#[derive(Debug,Clone)]
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

impl<P: xdr_codec::Pack<Out>, Out: xdr_codec::Write> xdr_codec::Pack<Out> for LibvirtMessage<P> {
    fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
        let mut sz: usize = 0;
        sz += try!(self.header.pack(out));
        sz += try!(self.payload.pack(out));
        Ok(sz)
    }
}

macro_rules! delegate_pack_impl {
    ($t:ty) => {
        impl<Out: xdr_codec::Write> xdr_codec::Pack<Out> for $t {
            fn pack(&self, out: &mut Out) -> xdr_codec::Result<usize> {
                self.0.pack(out)
            }
        }
    }
}

macro_rules! delegate_unpack_impl {
    ($t:ty) => {
        impl<In: xdr_codec::Read> xdr_codec::Unpack<In> for $t {
            fn unpack(mut input: &mut In) -> xdr_codec::Result<(Self, usize)> {
                let (inner, len) = try!(xdr_codec::Unpack::unpack(input));
                let mut pkt: $t = unsafe { ::std::mem::zeroed() };
                pkt.0 = inner;
                Ok((pkt, len))
            }
        }

    }
}

macro_rules! req {
    ($name: ident) => {
        #[derive(Debug)]
        pub struct $name(());
        delegate_pack_impl!($name);

        impl $name {
            pub fn new() -> Self {
                $name(())
            }
        }
    };

    ($name:ident : $inner:ident { $($f:ident : $t:ty => $e: expr),+ }) => {
        #[derive(Debug)]
        pub struct $name($inner);
        delegate_pack_impl!($name);

        impl $name {
            pub fn new($( $f: $t,)+) -> Self {
                let inner = $inner {
                    $(
                        $f: $e,
                    )+
                };
                $name(inner)
            }
        }
    };

    ($name:ident : $inner:ident { $($f:ident as $arg:ident : $t:ty => $e: expr),+ }) => {
        #[derive(Debug)]
        pub struct $name($inner);
        delegate_pack_impl!($name);

        impl $name {
            pub fn new($( $arg: $t,)+) -> Self {
                let inner = $inner {
                    $(
                        $f: $e,
                    )+
                };
                $name(inner)
            }
        }
    };



    ($name:ident : $inner:ident { $($f: ident => $e: expr),+ }) => {
        #[derive(Debug)]
        pub struct $name($inner);
        delegate_pack_impl!($name);

        impl $name {
            pub fn new() -> Self {
                let inner = $inner {
                    $(
                        $f: $e,
                    )+
                };
                $name(inner)
            }
        }
    };


    ($name:ident : $inner:ident { $($f: ident : $t: ty),+ }) => {
        #[derive(Debug)]
        pub struct $name($inner);
        delegate_pack_impl!($name);

        impl $name {
            pub fn new($( $f: $t,)+) -> Self {
                let inner = $inner {
                    $(
                        $f,
                    )+
                };
                $name(inner)
            }
        }
    };

    // argument renaming
    ($name:ident : $inner:ident { $($f: ident as $arg: ident : $t: ty),+ }) => {
        #[derive(Debug)]
        pub struct $name($inner);
        delegate_pack_impl!($name);

        impl $name {
            pub fn new($( $arg: $t,)+) -> Self {
                let inner = $inner {
                    $(
                        $f: $arg,
                    )+
                };
                $name(inner)
            }
        }
    };
}

macro_rules! resp {
    ($name: ident) => {
        #[derive(Debug)]
        pub struct $name(());
        delegate_unpack_impl!($name);

        impl Into<()> for $name {
            fn into(self) -> () {
                ()
            }
        }
    };

    ($name: ident : $inner: ty) => {
        #[derive(Debug)]
        pub struct $name($inner);
        delegate_unpack_impl!($name);
    };
}

macro_rules! rpc {
    ($req:ident => $resp:ident) => {
        impl<R: ::std::io::Read> LibvirtRpc<R> for $req {
            type Response = $resp;
        }
    }
}

/// Auth list request must be the first request
req!(AuthListRequest);
resp!(AuthListResponse: generated::remote_auth_list_ret);
rpc!(AuthListRequest => AuthListResponse);

/// Connect open request
use generated::remote_connect_open_args;
req!(ConnectOpenRequest: remote_connect_open_args {
     name => Some(generated::remote_nonnull_string("qemu:///system".to_string())),
     flags => 0
});
resp!(ConnectOpenResponse);
rpc!(ConnectOpenRequest => ConnectOpenResponse);

/// Version request
req!(GetLibVersionRequest);
resp!(GetLibVersionResponse: generated::remote_connect_get_lib_version_ret);
rpc!(GetLibVersionRequest => GetLibVersionResponse);

impl GetLibVersionResponse {
    pub fn version(&self) -> (u32, u32, u32) {
        let mut version = (self.0).lib_ver;

        let major = version / 1000000;
        version %= 1000000;
        let minor = version / 1000;
        version %= 1000;
        let micro = version;

        (major as u32, minor as u32, micro as u32)
    }
}

use generated::remote_connect_list_defined_domains_args;
req!(ListDefinedDomainsRequest: remote_connect_list_defined_domains_args {
    maxnames => generated::REMOTE_DOMAIN_LIST_MAX as i32
});
resp!(ListDefinedDomainsResponse: generated::remote_connect_list_defined_domains_ret);
rpc!(ListDefinedDomainsRequest => ListDefinedDomainsResponse);

impl ListDefinedDomainsResponse {
    pub fn get_domain_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        for name in &(self.0).names {
            names.push(name.0.to_string());
        }
        names
    }
}

use generated::remote_domain_define_xml_flags_args;
req!(DomainDefineXMLRequest: remote_domain_define_xml_flags_args {
    xml: &str => generated::remote_nonnull_string(xml.to_string()),
    flags: u32 => flags
});

resp!(DomainDefineXMLResponse: generated::remote_domain_define_xml_flags_ret);
rpc!(DomainDefineXMLRequest => DomainDefineXMLResponse);

impl ::std::convert::Into<Domain> for DomainDefineXMLResponse {
    fn into(self) -> Domain {
        Domain (self.0.dom)
    }
}

impl DomainDefineXMLResponse {
    pub fn get_domain(&self) -> Domain {
        Domain ((self.0).dom.clone())
    }
}

use generated::remote_domain_shutdown_args;
req!(DomainShutdownRequest: remote_domain_shutdown_args {
    dom: &Domain => dom.0.to_owned()
});

resp!(DomainShutdownResponse);
rpc!(DomainShutdownRequest => DomainShutdownResponse);

use generated::remote_domain_reboot_args;
req!(DomainRebootRequest: remote_domain_reboot_args {
    dom: &Domain => dom.0.to_owned(),
    flags: u32 => flags
});

resp!(DomainRebootResponse);
rpc!(DomainRebootRequest => DomainRebootResponse);

use generated::remote_domain_reset_args;
req!(DomainResetRequest: remote_domain_reset_args {
    dom: &Domain => dom.0.to_owned(),
    flags: u32 => flags
});

resp!(DomainResetResponse);
rpc!(DomainResetRequest => DomainResetResponse);

use generated::remote_domain_undefine_flags_args;
req!(DomainUndefineRequest: remote_domain_undefine_flags_args {
    dom: Domain => dom.0,
    flags: u32 => flags
});

resp!(DomainUndefineResponse);
rpc!(DomainUndefineRequest => DomainUndefineResponse);

#[allow(non_snake_case)]
pub mod DomainCreateFlags {
    bitflags! {
        pub flags DomainCreateFlags: u32 {
            /// Launch guest in paused state
            const START_PAUSED = 1,
            /// Automatically kill guest when virConnectPtr is closed
            const START_AUTODESTROY = 2,
            /// Avoid file system cache pollution
            const START_BYPASS_CACHE = 4,
            /// Boot, discarding any managed save
            const START_FORCE_BOOT = 8,
            /// Validate the XML document against schema
            const START_VALIDATE = 16,
        }
    }
}

use generated::remote_domain_create_with_flags_args;
req!(DomainCreateRequest: remote_domain_create_with_flags_args {
    dom: Domain => dom.0,
    flags: DomainCreateFlags::DomainCreateFlags => flags.bits()
});

resp!(DomainCreateResponse: generated::remote_domain_create_with_flags_ret);
rpc!(DomainCreateRequest => DomainCreateResponse);

impl ::std::convert::Into<Domain> for DomainCreateResponse {
    fn into(self) -> Domain {
        Domain (self.0.dom)
    }
}

impl DomainCreateResponse {
    pub fn get_domain(&self) -> Domain {
        Domain ((self.0).dom.clone())
    }
}

#[allow(non_snake_case)]
pub mod DomainDestroyFlags {
    bitflags! {
        pub flags DomainDestroyFlags: u32 {
            /// Default behavior - could lead to data loss!!
            const DESTROY_DEFAULT = 0,
            /// Only SIGTERM, no SIGKILL
            const DESTROY_GRACEFUL = 1,
        }
    }
}
use generated::remote_domain_destroy_flags_args;
req!(DomainDestroyRequest: remote_domain_destroy_flags_args {
    dom: &Domain => dom.0.clone(),
    flags: DomainDestroyFlags::DomainDestroyFlags => flags.bits()
});

resp!(DomainDestroyResponse);
rpc!(DomainDestroyRequest => DomainDestroyResponse);

#[allow(non_snake_case)]
pub mod ListAllDomainsFlags {
    bitflags! {
        pub flags ListAllDomainsFlags: u32 {
            const DOMAINS_ACTIVE	=	1,
            const DOMAINS_INACTIVE	=	2,
            const DOMAINS_PERSISTENT	=	4,
            const DOMAINS_TRANSIENT	=	8,
            const DOMAINS_RUNNING	=	16,
            const DOMAINS_PAUSED	=	32,
            const DOMAINS_SHUTOFF	=	64,
            const DOMAINS_OTHER	=	128,
            const DOMAINS_MANAGEDSAVE	=	256,
            const DOMAINS_NO_MANAGEDSAVE	=	512,
            const DOMAINS_AUTOSTART	=	1024,
            const DOMAINS_NO_AUTOSTART	=	2048,
            const DOMAINS_HAS_SNAPSHOT	=	4096,
            const DOMAINS_NO_SNAPSHOT	=	8192,
        }
    }
}

#[derive(Debug)]
pub struct ListAllDomainsRequest(generated::remote_connect_list_all_domains_args);

impl ListAllDomainsRequest {
    pub fn new(flags: ListAllDomainsFlags::ListAllDomainsFlags) -> Self {
        let payload = generated::remote_connect_list_all_domains_args {
            need_results: 1,
            flags: flags.bits(),
        };
        ListAllDomainsRequest(payload)
    }
}

delegate_pack_impl!(ListAllDomainsRequest);

#[derive(Debug)]
pub struct ListAllDomainsResponse(generated::remote_connect_list_all_domains_ret);

impl ::std::convert::Into<Vec<Domain>> for ListAllDomainsResponse {
    fn into(self) -> Vec<Domain> {
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

use generated::remote_connect_domain_event_register_any_args;
req!(DomainEventRegisterAnyRequest: remote_connect_domain_event_register_any_args {
    eventID as event: i32
});

resp!(DomainEventRegisterAnyResponse);
rpc!(DomainEventRegisterAnyRequest => DomainEventRegisterAnyResponse);

use generated::remote_connect_domain_event_callback_register_any_args;
req!(DomainEventCallbackRegisterAnyRequest: remote_connect_domain_event_callback_register_any_args {
    eventID as event: i32 => event,
    dom as domain: Option<&Domain> => domain.map(|dom| Box::new(dom.0.clone()))
});

resp!(DomainEventCallbackRegisterAnyResponse: generated::remote_connect_domain_event_callback_register_any_ret);
rpc!(DomainEventCallbackRegisterAnyRequest => DomainEventCallbackRegisterAnyResponse);

impl DomainEventCallbackRegisterAnyResponse {
    pub fn callback_id(&self) -> i32 {
        self.0.callbackID
    }
}

use generated::remote_domain_lookup_by_uuid_args;
req!(DomainLookupByUuidRequest: remote_domain_lookup_by_uuid_args {
    uuid: &::uuid::Uuid => generated::remote_uuid(uuid.as_bytes().clone())
});

resp!(DomainLookupByUuidResponse: generated::remote_domain_lookup_by_uuid_ret);
rpc!(DomainLookupByUuidRequest => DomainLookupByUuidResponse);

impl DomainLookupByUuidResponse {
    pub fn domain(&self) -> Domain {
        Domain ((self.0).dom.clone())
    }
}

/* http://libvirt.org/html/libvirt-libvirt-domain.html#virDomainEventCrashedDetailType */
#[derive(Debug)]
pub enum EventCrashedDetailType {
    /// Guest was panicked
    Panicked = 0,
}

/* http://libvirt.org/html/libvirt-libvirt-domain.html#virDomainEventStartedDetailType */
#[derive(Debug)]
pub enum EventStartedDetailType {
    /// Normal startup from boot
    Booted = 0,
    /// Incoming migration from another host
    Migrated = 1,
    /// Restored from a state file
    Restored = 2,
    /// Restored from snapshot
    FromSnapshot = 3,
    /// Started due to wakeup event
    Wakeup = 4,
}

/* http://libvirt.org/html/libvirt-libvirt-domain.html#virDomainEventStoppedDetailType */
#[derive(Debug)]
pub enum EventStoppedDetailType {
    /// Normal shutdown
    Shutdown = 0,
    /// Forced poweroff from host
    Destroyed = 1,
    /// Guest crashed
    Crashed = 2,
    /// Migrated off to another host
    Migrated = 3,
    /// Saved to a state file
    Saved = 4,
    /// Host emulator/mgmt failed
    Failed = 5,
    /// Offline snapshot loaded
    FromSnapshot = 6,
}

/* http://libvirt.org/html/libvirt-libvirt-domain.html#virDomainEventSuspendedDetailType */
#[derive(Debug)]
pub enum EventSuspendedDetailType {
    /// Normal suspend due to admin pause
    Paused = 0,
    /// Suspended for offline migration
    Migrated = 1,
    /// Suspended due to a disk I/O error
    IoError = 2,
    /// Suspended due to a watchdog firing
    Watchdog = 3,
    /// Restored from paused state file
    Restored = 4,
    /// Restored from paused snapshot
    FromSnapshot = 5,
    /// Suspended after failure during libvirt API call
    ApiError = 6,
    /// Suspended for post-copy migration
    PostCopy = 7,
    /// Suspended after failed post-copy
    PostCopyFailed = 8,
}

/* http://libvirt.org/html/libvirt-libvirt-domain.html#virDomainEventResumedDetailType */
#[derive(Debug)]
pub enum EventResumedDetailType {
    /// Normal resume due to admin unpause
    Unpaused = 0,
    /// Resumed for completion of migration
    Migrated = 1,
    /// Resumed from snapshot
    FromSnapshot = 2,
    /// Resumed, but migration is still running in post-copy mode
    PostCopy = 3,
}

/* http://libvirt.org/html/libvirt-libvirt-domain.html#virDomainEventDefinedDetailType */
#[derive(Debug)]
pub enum EventDefinedDetailType {
    /// Newly created config file
    Added =	0,
    /// Changed config file	
    Updated = 1,
    /// Domain was renamed
    Renamed = 2,
    /// Config was restored from a snapshot
    FromSnapshot = 3,
}

/* http://libvirt.org/html/libvirt-libvirt-domain.html#virDomainEventUndefinedDetailType */
#[derive(Debug)]
pub enum EventUndefinedDetailType {
    /// Deleted the config file
    Removed = 0,
    /// Domain was renamed
    Renamed = 1,
}

/* http://libvirt.org/html/libvirt-libvirt-domain.html#virDomainEventShutdownDetailType */
#[derive(Debug)]
pub enum EventShutdownDetailType {
    /// Guest finished shutdown sequence
    Finished = 0, 
}

/* http://libvirt.org/html/libvirt-libvirt-domain.html#virDomainEventPMSuspendedDetailType */
#[derive(Debug)]
pub enum EventPmSuspendedDetailType {
    /// Guest was PM suspended to memory
    Memory = 0,
    /// Guest was PM suspended to disk
    Disk = 1,
}

#[derive(Debug)]
pub enum DomainEventInfo {
    Defined(EventDefinedDetailType),
    Undefined(EventUndefinedDetailType),
    Started(EventStartedDetailType),
    Suspended(EventSuspendedDetailType),
    Stopped(EventStoppedDetailType),
    Shutdown(EventShutdownDetailType),
    Resumed(EventResumedDetailType),
    Crashed(EventCrashedDetailType),
    PmSuspended(EventPmSuspendedDetailType),
    Other(i32, i32)
}

#[derive(Debug)]
pub struct DomainEvent {
    pub domain: Domain,
    pub info: DomainEventInfo,
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

impl From<generated::remote_domain_event_callback_lifecycle_msg> for DomainEvent {
    fn from(ev: generated::remote_domain_event_callback_lifecycle_msg) -> Self {
        use ::std::mem;
        let info = match ev.msg.event {
            VIR_DOMAIN_EVENT_DEFINED => {
                let detail = unsafe { mem::transmute(ev.msg.detail as u8) };
                DomainEventInfo::Defined(detail)
            }
            VIR_DOMAIN_EVENT_UNDEFINED => {
                let detail = unsafe { mem::transmute(ev.msg.detail as u8) };
                DomainEventInfo::Undefined(detail)
            }
            VIR_DOMAIN_EVENT_STARTED => {
                let detail = unsafe { mem::transmute(ev.msg.detail as u8) };
                DomainEventInfo::Started(detail)
            }
            VIR_DOMAIN_EVENT_SUSPENDED => {
                let detail = unsafe { mem::transmute(ev.msg.detail as u8) };
                DomainEventInfo::Suspended(detail)
            }
            VIR_DOMAIN_EVENT_STOPPED => {
                let detail = unsafe { mem::transmute(ev.msg.detail as u8) };
                DomainEventInfo::Stopped(detail)
            }
            VIR_DOMAIN_EVENT_RESUMED => {
                let detail = unsafe { mem::transmute(ev.msg.detail as u8) };
                DomainEventInfo::Resumed(detail)
            }
            VIR_DOMAIN_EVENT_SHUTDOWN => {
                let detail = unsafe { mem::transmute(ev.msg.detail as u8) };
                DomainEventInfo::Shutdown(detail)
            }
            VIR_DOMAIN_EVENT_CRASHED => {
                let detail = unsafe { mem::transmute(ev.msg.detail as u8) };
                DomainEventInfo::Crashed(detail)
            }
            VIR_DOMAIN_EVENT_PMSUSPENDED => {
                let detail = unsafe { mem::transmute(ev.msg.detail as u8) };
                DomainEventInfo::PmSuspended(detail)
            }
            i => {
                DomainEventInfo::Other(i, ev.msg.detail)
            }
        };
        let domain = Domain(ev.msg.dom);
        DomainEvent { domain, info }
    }
}

// http://libvirt.org/html/libvirt-libvirt-storage.html#virConnectListAllStoragePoolsFlags
#[allow(non_snake_case)]
pub mod ListAllStoragePoolsFlags {
    bitflags! {
        pub flags ListAllStoragePoolsFlags: u32 {
            const LIST_STORAGE_POOLS_INACTIVE	=	1,
            const LIST_STORAGE_POOLS_ACTIVE	=	2,
            const LIST_STORAGE_POOLS_PERSISTENT	=	4,
            const LIST_STORAGE_POOLS_TRANSIENT	=	8,
            const LIST_STORAGE_POOLS_AUTOSTART	=	16,
            const LIST_STORAGE_POOLS_NO_AUTOSTART	=	32,
            // List pools by type
            const LIST_STORAGE_POOLS_DIR	=	64,
            const LIST_STORAGE_POOLS_FS	=	128,
            const LIST_STORAGE_POOLS_NETFS	=	256,
            const LIST_STORAGE_POOLS_LOGICAL	=	512,
            const LIST_STORAGE_POOLS_DISK	=	1024,
            const LIST_STORAGE_POOLS_ISCSI	=	2048,
            const LIST_STORAGE_POOLS_SCSI	=	4096,
            const LIST_STORAGE_POOLS_MPATH	=	8192,
            const LIST_STORAGE_POOLS_RBD	=	16384,
            const LIST_STORAGE_POOLS_SHEEPDOG	=	32768,
            const LIST_STORAGE_POOLS_GLUSTER	=	65536,
            const LIST_STORAGE_POOLS_ZFS	=	131072,
            const LIST_STORAGE_POOLS_VSTORAGE = 262144,
        }
    }
}

#[derive(Debug)]
pub struct StoragePool(generated::remote_nonnull_storage_pool);

impl From<generated::remote_nonnull_storage_pool> for StoragePool {
    fn from(inner: generated::remote_nonnull_storage_pool) -> Self {
        StoragePool(inner)
    }
}

#[derive(Debug)]
pub struct ListAllStoragePoolsRequest(generated::remote_connect_list_all_storage_pools_args);
delegate_pack_impl!(ListAllStoragePoolsRequest);

impl ListAllStoragePoolsRequest {
    pub fn new(flags: ListAllStoragePoolsFlags::ListAllStoragePoolsFlags) -> Self {
        let pl = generated::remote_connect_list_all_storage_pools_args {
            need_results: 1,
            flags: flags.bits(),
        };
        ListAllStoragePoolsRequest(pl)
    }
}

#[derive(Debug)]
pub struct ListAllStoragePoolsResponse(generated::remote_connect_list_all_storage_pools_ret);
delegate_unpack_impl!(ListAllStoragePoolsResponse);

impl Into<Vec<StoragePool>> for ListAllStoragePoolsResponse {
    fn into(self) -> Vec<StoragePool> {
        let mut result = Vec::new();
        for pool in self.0.pools {
            result.push(pool.into());
        }
        result
    }
}

rpc!(ListAllStoragePoolsRequest => ListAllStoragePoolsResponse);

use generated::remote_storage_pool_define_xml_args;
req!(StoragePoolDefineXmlRequest: remote_storage_pool_define_xml_args {
    xml: &str => generated::remote_nonnull_string(xml.to_string()),
    flags: u32 => flags
});

resp!(StoragePoolDefineXmlResponse: generated::remote_storage_pool_define_xml_ret);
rpc!(StoragePoolDefineXmlRequest => StoragePoolDefineXmlResponse);

impl Into<StoragePool> for StoragePoolDefineXmlResponse {
    fn into(self) -> StoragePool {
        StoragePool(self.0.pool)
    }
}

use generated::remote_storage_pool_lookup_by_uuid_args;
req!(StoragePoolLookupByUuidRequest: remote_storage_pool_lookup_by_uuid_args {
    uuid: &::uuid::Uuid => generated::remote_uuid(uuid.as_bytes().clone())
});

resp!(StoragePoolLookupByUuidResponse: generated::remote_storage_pool_lookup_by_uuid_ret);
rpc!(StoragePoolLookupByUuidRequest => StoragePoolLookupByUuidResponse);

impl Into<StoragePool> for StoragePoolLookupByUuidResponse {
    fn into(self) -> StoragePool {
        StoragePool(self.0.pool)
    }
}

use generated::remote_storage_pool_lookup_by_name_args;
req!(StoragePoolLookupByNameRequest: remote_storage_pool_lookup_by_name_args {
    name: &str => generated::remote_nonnull_string(name.to_string())
});

resp!(StoragePoolLookupByNameResponse: generated::remote_storage_pool_lookup_by_name_ret);
rpc!(StoragePoolLookupByNameRequest => StoragePoolLookupByNameResponse);

impl Into<StoragePool> for StoragePoolLookupByNameResponse {
    fn into(self) -> StoragePool {
        StoragePool(self.0.pool)
    }
}

use generated::remote_storage_pool_create_args;
req!(StoragePoolCreateRequest: remote_storage_pool_create_args {
    pool: &StoragePool => pool.0.clone(),
    flags: u32 => flags
});
resp!(StoragePoolCreateResponse);
rpc!(StoragePoolCreateRequest => StoragePoolCreateResponse);

use generated::remote_storage_pool_destroy_args;
req!(StoragePoolDestroyRequest: remote_storage_pool_destroy_args {
    pool: &StoragePool => pool.0.clone()
});
resp!(StoragePoolDestroyResponse);
rpc!(StoragePoolDestroyRequest => StoragePoolDestroyResponse);

use generated::remote_storage_pool_undefine_args;
req!(StoragePoolUndefineRequest: remote_storage_pool_undefine_args {
    pool: StoragePool => pool.0
});
resp!(StoragePoolUndefineResponse);
rpc!(StoragePoolUndefineRequest => StoragePoolUndefineResponse);

use generated::remote_storage_pool_list_volumes_args;
req!(StoragePoolListVolumesRequest: remote_storage_pool_list_volumes_args {
    pool: &StoragePool => pool.0.clone(),
    maxnames: i32 => maxnames
});
resp!(StoragePoolListVolumesResponse: generated::remote_storage_pool_list_volumes_ret);
rpc!(StoragePoolListVolumesRequest => StoragePoolListVolumesResponse);

impl Into<Vec<String>> for StoragePoolListVolumesResponse {
    fn into(self) -> Vec<String> {
        self.0.names.into_iter().map(|nns| nns.0).collect()
    }
}

#[derive(Debug)]
pub struct Volume(generated::remote_nonnull_storage_vol);

impl Volume {
    pub fn name(&self) -> &str {
        &self.0.name.0
    }

    pub fn key(&self) -> &str {
        &self.0.key.0
    }

    pub fn pool_name(&self) -> &str {
        &self.0.pool.0
    }
}

impl From<generated::remote_nonnull_storage_vol> for Volume {
    fn from(inner: generated::remote_nonnull_storage_vol) -> Self {
        Volume(inner)
    }
}

use generated::remote_storage_pool_list_all_volumes_args;
req!(StoragePoolListAllVolumesRequest: remote_storage_pool_list_all_volumes_args {
    pool: &StoragePool => pool.0.clone(),
    need_results: i32 => need_results,
    flags: u32 => flags
});
resp!(StoragePoolListAllVolumesResponse: generated::remote_storage_pool_list_all_volumes_ret);
rpc!(StoragePoolListAllVolumesRequest => StoragePoolListAllVolumesResponse);

impl Into<Vec<Volume>> for StoragePoolListAllVolumesResponse {
    fn into(self) -> Vec<Volume> {
        self.0.vols.into_iter().map(|vol| vol.into()).collect()
    }
}

#[allow(non_snake_case)]
pub mod StorageVolCreateXmlFlags {
    bitflags! {
        pub flags StorageVolCreateXmlFlags: u32 {
            const VOL_CREATE_PREALLOC_METADATA = 1,
            /// perform a btrfs lightweight copy
            const VOL_CREATE_REFLINK = 2,
        }
    }
}

use generated::remote_storage_vol_create_xml_args;
req!(StorageVolCreateXmlRequest: remote_storage_vol_create_xml_args {
    pool: &StoragePool => pool.0.clone(),
    xml: &str => generated::remote_nonnull_string(xml.to_owned()),
    flags: StorageVolCreateXmlFlags::StorageVolCreateXmlFlags => flags.bits()
});
resp!(StorageVolCreateXmlResponse: generated::remote_storage_vol_create_xml_ret);
rpc!(StorageVolCreateXmlRequest => StorageVolCreateXmlResponse);

impl Into<Volume> for StorageVolCreateXmlResponse {
    fn into(self) -> Volume {
        self.0.vol.into()
    }
}

use generated::remote_storage_vol_create_xml_from_args;
req!(StorageVolCreateXmlFromRequest: remote_storage_vol_create_xml_from_args {
    pool: &StoragePool => pool.0.clone(),
    xml: &str => generated::remote_nonnull_string(xml.to_owned()),
    clonevol: &Volume => clonevol.0.clone(),
    flags: StorageVolCreateXmlFlags::StorageVolCreateXmlFlags => flags.bits()
});
resp!(StorageVolCreateXmlFromResponse: generated::remote_storage_vol_create_xml_from_ret);
rpc!(StorageVolCreateXmlFromRequest => StorageVolCreateXmlFromResponse);

impl Into<Volume> for StorageVolCreateXmlFromResponse {
    fn into(self) -> Volume {
        self.0.vol.into()
    }
}

use generated::remote_storage_vol_delete_args;
req!(StorageVolDeleteRequest: remote_storage_vol_delete_args {
    vol: Volume => vol.0.clone(),
    flags: u32 => flags
});
resp!(StorageVolDeleteResponse);
rpc!(StorageVolDeleteRequest => StorageVolDeleteResponse);

use generated::remote_storage_vol_wipe_args;
req!(StorageVolWipeRequest: remote_storage_vol_wipe_args {
    vol: &Volume => vol.0.clone(),
    flags: u32 => flags
});
resp!(StorageVolWipeResponse);
rpc!(StorageVolWipeRequest => StorageVolWipeResponse);

use generated::remote_storage_vol_lookup_by_name_args;
req!(StorageVolLookupByNameRequest: remote_storage_vol_lookup_by_name_args {
    pool: &StoragePool => pool.0.clone(),
    name: &str => generated::remote_nonnull_string(name.to_owned())
});
resp!(StorageVolLookupByNameResponse: generated::remote_storage_vol_lookup_by_name_ret);
rpc!(StorageVolLookupByNameRequest => StorageVolLookupByNameResponse);

impl Into<Volume> for StorageVolLookupByNameResponse {
    fn into(self) -> Volume {
        Volume(self.0.vol)
    }
}

#[allow(non_snake_case)]
pub mod StorageVolResizeFlags {
    bitflags! {
        pub flags StorageVolResizeFlags: u32 {
            /// force allocation of new size
            const RESIZE_ALLOCATE = 1,
            /// size is relative to current
            const RESIZE_DELTA = 2,
            /// allow decrease in capacity
            const RESIZE_SHRINK = 4,
        }
    }
}

use generated::remote_storage_vol_resize_args;
req!(StorageVolResizeRequest: remote_storage_vol_resize_args {
    vol: &Volume => vol.0.clone(),
    capacity: u64 => capacity,
    flags: StorageVolResizeFlags::StorageVolResizeFlags => flags.bits()
});
resp!(StorageVolResizeResponse);
rpc!(StorageVolResizeRequest => StorageVolResizeResponse);

use generated::remote_domain_screenshot_args;
req!(DomainScreenshotRequest: remote_domain_screenshot_args {
    dom: &Domain => dom.0.clone(),
    screen: u32 => screen,
    flags: u32 => flags
});
resp!(DomainScreenshotResponse: generated::remote_domain_screenshot_ret);
rpc!(DomainScreenshotRequest => DomainScreenshotResponse);

impl Into<Option<String>> for DomainScreenshotResponse {
    fn into(self) -> Option<String> {
        self.0.mime.map(|s| s.0)
    }
}

use generated::remote_storage_vol_download_args;
req!(StorageVolDownloadRequest: remote_storage_vol_download_args {
    vol: &Volume => vol.0.clone(),
    offset: u64 => offset,
    length: u64 => length,
    flags: u32 => flags
});
resp!(StorageVolDownloadResponse);
rpc!(StorageVolDownloadRequest => StorageVolDownloadResponse);

use generated::remote_storage_vol_upload_args;
req!(StorageVolUploadRequest: remote_storage_vol_upload_args {
    vol: &Volume => vol.0.clone(),
    offset: u64 => offset,
    length: u64 => length,
    flags: u32 => flags
});
resp!(StorageVolUploadResponse);
rpc!(StorageVolUploadRequest => StorageVolUploadResponse);

use generated::remote_domain_get_info_args;
req!(DomainGetInfoRequest: remote_domain_get_info_args {
    dom: &Domain => dom.0.clone()
});
resp!(DomainGetInfoResponse: generated::remote_domain_get_info_ret);
rpc!(DomainGetInfoRequest => DomainGetInfoResponse);

use generated::remote_domain_attach_device_flags_args;
req!(DomainAttachDeviceRequest: remote_domain_attach_device_flags_args {
    dom: &Domain => dom.0.clone(),
    xml: &str => generated::remote_nonnull_string(xml.to_owned()),
    flags: DomainModificationImpact::DomainModificationImpact => flags.bits()
});
resp!(DomainAttachDeviceResponse);
rpc!(DomainAttachDeviceRequest => DomainAttachDeviceResponse);

use generated::remote_domain_detach_device_flags_args;
req!(DomainDetachDeviceRequest: remote_domain_detach_device_flags_args {
    dom: &Domain => dom.0.clone(),
    xml: &str => generated::remote_nonnull_string(xml.to_owned()),
    flags: DomainModificationImpact::DomainModificationImpact => flags.bits()
});
resp!(DomainDetachDeviceResponse);
rpc!(DomainDetachDeviceRequest => DomainDetachDeviceResponse);

use generated::remote_domain_get_xml_desc_args;
req!(DomainGetXmlDescRequest: remote_domain_get_xml_desc_args {
    dom: &Domain => dom.0.clone(),
    flags: DomainXmlFlags::DomainXmlFlags => flags.bits()
});
resp!(DomainGetXmlDescResponse: generated::remote_domain_get_xml_desc_ret);
rpc!(DomainGetXmlDescRequest => DomainGetXmlDescResponse);

impl Into<String> for DomainGetXmlDescResponse {
    fn into(self) -> String {
        (self.0).xml.0
    }
}

#[allow(non_snake_case)]
pub mod DomainXmlFlags {
    bitflags! {
        pub flags DomainXmlFlags: u32 {
            /// dump security sensitive information too
            const SECURE	= 1,
            /// dump inactive domain information
            const INACTIVE	=	2,
            /// update guest CPU requirements according to host CPU
            const UPDATE_CPU	=	4,
            /// dump XML suitable for migration
            const MIGRATABLE	=	8,
        }
    }
}

#[allow(non_snake_case)]
pub mod DomainModificationImpact {
    bitflags! {
        pub flags DomainModificationImpact: u32 {
            /// Affect current domain state.
            const AFFECT_CURRENT = 0,

            /// Affect running domain state.
            const AFFECT_LIVE = 1,

            /// Affect persistent domain state.
            const AFFECT_CONFIG = 2,
        }
    }
}

#[derive(Debug)]
pub struct DomainInfo(DomainGetInfoResponse);

impl DomainInfo {
    pub fn get_state(&self) -> DomainState {
        DomainState::from((self.0).0.state as u8)
    }
}

impl From<DomainGetInfoResponse> for DomainInfo {
    fn from(resp: DomainGetInfoResponse) -> Self {
        DomainInfo(resp)
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum DomainState {
    /// no state
    NoState = 0,
    /// the domain is running
    Running = 1,
    /// the domain is blocked on resource
    Blocked = 2,
    /// the domain is paused by user
    Paused = 3,
    /// the domain is being shut down
    Shutdown = 4,
    /// the domain is shut off
    Shutoff = 5,
    /// the domain is crashed
    Crashed = 6,
    /// the domain is suspended by guest power management
    PmSuspended = 7
}

impl From<u8> for DomainState {
    fn from(v: u8) -> Self {
        unsafe { ::std::mem::transmute(v) }
    }
}

#[derive(Debug)]
#[repr(u32)]
pub enum ErrorCode {
    OK	=	0,
    /// internal error
    InternalError	=	1, 
    /// memory allocation failure
    NoMemory	=	2,
	/// no support for this function
    NoSupport	=	3,
    /// could not resolve hostname
    UnknownHost	=	4,
    /// can't connect to hypervisor
    NoConnect	=	5,
    /// invalid connection object
    InvalidConn	=	6,
    /// invalid domain object
    InvalidDomain	=	7,
    /// invalid function argument
    InvalidArg	=	8,
    /// a command to hypervisor failed
    OperationFailed	=	9,
    /// a HTTP GET command to failed
    GetFailed	=	10,
    /// a HTTP POST command to failed
    PostFailed	=	11,
    /// unexpected HTTP error code
    HttpError	=	12,
    /// failure to serialize an S-Expr
    SexprSerial	=	13,
    /// could not open Xen hypervisor control
    NoXen	=	14,
    /// failure doing an hypervisor call
    XenCall	=	15,
    /// unknown OS type
    OsType	=	16,
    /// missing kernel information
    NoKernel =	17,
    /// missing root device information
    NoRoot =	18,
    /// missing source device information
    NoSource	=	19,
    /// missing target device information
    NoTarget	=	20,
    /// missing domain name information
    NoName	=	21,
    /// missing domain OS information
    NoOs	=	22,
    /// missing domain devices information
    NoDevice	=	23,
    /// could not open Xen Store control
    NoXenstore	=	24,
    /// too many drivers registered
    DriverFull	=	25,
    /// not supported by the drivers (DEPRECATED)
    CallFailed	=	26,
    /// an XML description is not well formed or broken
    XmlError	=	27,
    /// the domain already exist
    DomExist	=	28,
    /// operation forbidden on read-only connections
    OperationDenied	=	29,
    /// failed to open a conf file
    OpenFailed	=	30,
    /// failed to read a conf file
    ReadFailed	=	31,
    /// failed to parse a conf file
    ParseFailed	=	32,
    /// failed to parse the syntax of a conf file
    ConfSyntax	=	33,
    /// failed to write a conf file
    WriteFailed	=	34,
    /// detail of an XML error
    XmlDetail	=	35,
    /// invalid network object
    InvalidNetwork	=	36,
    /// the network already exist
    NetworkExist	=	37,
    /// general system call failure
    SystemError	=	38,
    /// some sort of RPC error
    Rpc	=	39,
    /// error from a GNUTLS call
    GnutlsError	=	40,
    /// failed to start network
    VirWarNoNetwork	=	41,
    /// domain not found or unexpectedly disappeared
    NoDomain	=	42,
    /// network not found
    NoNetwork	=	43,
    /// invalid MAC address
    InvalidMac	=	44,
    /// authentication failed
    AuthFailed	=	45,
    /// invalid storage pool object
    InvalidStoragePool	=	46,
    /// invalid storage vol object
    InvalidStorageVol	=	47,
    /// failed to start storage
    VirWarNoStorage	=	48,
    /// storage pool not found
    NoStoragePool	=	49,
    /// storage volume not found
    NoStorageVol	=	50,
    /// failed to start node driver
    VirWarNoNode	=	51,
    /// invalid node device object
    InvalidNodeDevice	=	52,
    /// node device not found
    NoNodeDevice	=	53,
    /// security model not found
    NoSecurityModel	=	54,
    /// operation is not applicable at this time
    OperationInvalid	=	55,
    /// failed to start interface driver
    VirWarNoInterface	=	56,
    /// interface driver not running
    NoInterface	=	57,
    /// invalid interface object
    InvalidInterface	=	58,
    /// more than one matching interface found
    MultipleInterfaces	=	59,
    /// failed to start nwfilter driver
    VirWarNoNwfilter	=	60,
    /// invalid nwfilter object
    InvalidNwfilter	=	61,
    /// nw filter pool not found
    NoNwfilter	=	62,
    /// nw filter pool not found
    BuildFirewall	=	63,
    /// failed to start secret storage
    VirWarNoSecret	=	64,
    /// invalid secret
    InvalidSecret	=	65,
    /// secret not found
    NoSecret	=	66,
    /// unsupported configuration construct
    ConfigUnsupported	=	67,
    /// timeout occurred during operation
    OperationTimeout	=	68,
    /// a migration worked, but making the VM persist on the dest host failed
    MigratePersistFailed	=	69,
    /// a synchronous hook script failed
    HookScriptFailed	=	70,
    /// invalid domain snapshot
    InvalidDomainSnapshot	=	71,
    /// domain snapshot not found
    NoDomainSnapshot	=	72,
    /// stream pointer not valid
    InvalidStream	=	73,
    /// valid API use but unsupported by the given driver
    ArgumentUnsupported	=	74,
    /// storage pool probe failed
    StorageProbeFailed	=	75,
    /// storage pool already built
    StoragePoolBuilt	=	76,
    /// force was not requested for a risky domain snapshot revert
    SnapshotRevertRisky	=	77,
    /// operation on a domain was canceled/aborted by user
    OperationAborted	=	78,
    /// authentication cancelled
    AuthCancelled	=	79,
    /// The metadata is not present
    NoDomainMetadata	=	80,
    /// Migration is not safe
    MigrateUnsafe	=	81,
    /// integer overflow
    Overflow	=	82,
    /// action prevented by block copy job
    BlockCopyActive	=	83,
    /// The requested operation is not supported
    OperationUnsupported	=	84,
    /// error in ssh transport driver
    Ssh	=	85,
    /// guest agent is unresponsive, not running or not usable
    AgentUnresponsive	=	86,
    /// resource is already in use
    ResourceBusy	=	87,
    /// operation on the object/resource was denied
    AccessDenied	=	88,
    /// error from a dbus service
    DbusService	=	89,
    /// the storage vol already exists
    StorageVolExist	=	90,
    /// given CPU is incompatible with host CP
    CpuIncompatible	=	91,
    /// XML document doesn't validate against schema
    XmlInvalidSchema	=	92,
    /// Finish API succeeded but it is expected to return NULL
    MigrateFinishOk	=	93,
    /// authentication unavailable
    AuthUnavailable	=	94,
    /// Server was not found
    NoServer	=	95,
    /// Client was not found
    NoClient	=	96,
    /// guest agent replies with wrong id to guest-sync command
    AgentUnsynced	=	97,
    /// error in libssh transport driver
    Libssh	=	98,
}

impl From<i32> for ErrorCode {
    fn from(v: i32) -> Self {
        unsafe { ::std::mem::transmute(v) }
    }
}

#[derive(Debug)]
#[repr(u32)]
pub enum ErrorDomain {
    None	=	0,
    /// Error at Xen hypervisor layer
    Xen	=	1,
    /// Error at connection with xend daemon
    Xend	=	2,	
    /// Error at connection with xen store
    Xenstore	=	3,
    /// Error in the S-Expression code
    Sexpr	=	4,
    /// Error in the XML code
    Xml	=	5,
    /// Error when operating on a domain
    Dom	=	6,
    /// Error in the XML-RPC code
    Rpc	=	7,
    /// Error in the proxy code; unused since 0.8.6
    Proxy	=	8,
    /// Error in the configuration file handling
    Conf	=	9,
    /// Error at the QEMU daemon
    Qemu	=	10,
    /// Error when operating on a network
    Net	=	11,
    /// Error from test driver
    Test	=	12,	
    /// Error from remote driver
    Remote	=	13,	
    /// Error from OpenVZ driver
    Openvz	=	14,
    /// Error at Xen XM layer
    Xenxm	=	15,
    /// Error in the Linux Stats code
    StatsLinux	=	16,
    /// Error from Linux Container driver
    Lxc	=	17,
    /// Error from storage driver
    Storage	=	18,
    /// Error from network config
    Network	=	19,
    /// Error from domain config
    Domain	=	20,
    /// Error at the UML driver
    Uml	=	21,
    /// Error from node device monitor
    Nodedev	=	22,
    /// Error from xen inotify layer
    XenInotify	=	23,
    /// Error from security framework
    Security	=	24,
    /// Error from VirtualBox driver
    Vbox	=	25,
    /// Error when operating on an interface
    Interface	=	26,
    /// The OpenNebula driver no longer exists. Retained for ABI/API compat only
    One	=	27,
    /// Error from ESX driver
    Esx	=	28,
    /// Error from IBM power hypervisor
    Phyp	=	29,
    /// Error from secret storage
    Secret	=	30,
    /// Error from CPU driver
    Cpu	=	31,
    /// Error from XenAPI
    Xenapi	=	32,
    /// Error from network filter driver
    Nwfilter	=	33,
    /// Error from Synchronous hooks
    Hook	=	34,
    /// Error from domain snapshot
    DomainSnapshot	=	35,
    /// Error from auditing subsystem
    Audit	=	36,
    /// Error from sysinfo/SMBIOS
    Sysinfo	=	37,
    /// Error from I/O streams
    Streams	=	38,
    /// Error from VMware driver
    Vmware	=	39,
    /// Error from event loop impl
    Event	=	40,
    /// Error from libxenlight driver
    Libxl	=	41,
    /// Error from lock manager
    Locking	=	42,
    /// Error from Hyper-V driver
    Hyperv	=	43,
    /// Error from capabilities
    Capabilities	=	44,
    /// Error from URI handling
    Uri	=	45,
    /// Error from auth handling
    Auth	=	46,
    /// Error from DBus
    Dbus	=	47,
    /// Error from Parallels
    Parallels	=	48,
    /// Error from Device
    Device	=	49,
    /// Error from libssh2 connection transport
    Ssh	=	50,
    /// Error from lockspace
    Lockspace	=	51,
    /// Error from initctl device communication
    Initctl	=	52,
    /// Error from identity code
    Identity	=	53,
    /// Error from cgroups
    Cgroup	=	54,
    /// Error from access control manager
    Access	=	55,
    /// Error from systemd code
    Systemd	=	56,
    /// Error from bhyve driver
    Bhyve	=	57,
    /// Error from crypto code
    Crypto	=	58,	
    /// Error from firewall
    Firewall	=	59,
    /// Error from polkit code
    Polkit	=	60,
    /// Error from thread utils
    Thread	=	61,
    /// Error from admin backend
    Admin	=	62,
    /// Error from log manager
    Logging	=	63,
    /// Error from Xen xl config code
    Xenxl	=	64,
    /// Error from perf
    Perf	=	65,
    /// Error from libssh connection transport
    Libssh	=	66,
}

impl From<i32> for ErrorDomain {
    fn from(v: i32) -> Self {
        unsafe { ::std::mem::transmute(v) }
    }
}