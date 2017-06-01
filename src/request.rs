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
    dom: Domain => dom.0,
    flags: DomainDestroyFlags::DomainDestroyFlags => flags.bits()
});

resp!(DomainDestroyResponse);
rpc!(DomainDestroyRequest => DomainDestroyResponse);

#[allow(non_snake_case)]
pub mod ListAllDomainFlags {
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
    pub fn new(flags: ListAllDomainFlags::ListAllDomainsFlags) -> Self {
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
    dom as domain: &Domain => Some(Box::new(domain.0.clone()))
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