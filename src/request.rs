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
    const PROCEDURE: ::remote_procedure;
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
            fn unpack(input: &mut In) -> xdr_codec::Result<(Self, usize)> {
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
    ($id:path, $req:ident => $resp:ident) => {
        impl<R: ::std::io::Read> LibvirtRpc<R> for $req {
            const PROCEDURE: ::remote_procedure = $id;
            type Response = $resp;
        }
    }
}

req!(NodeGetInfoRequest);
resp!(NodeGetInfoResponse: generated::remote_node_get_info_ret);
rpc!(remote_procedure::REMOTE_PROC_NODE_GET_INFO, NodeGetInfoRequest => NodeGetInfoResponse);

#[derive(Debug)]
pub struct NodeInfo(NodeGetInfoResponse);

impl From<NodeGetInfoResponse> for NodeInfo {
    fn from(resp: NodeGetInfoResponse) -> Self {
        NodeInfo(resp)
    }
}

impl NodeInfo {
    pub fn get_memory(&self) -> u64 {
        (self.0).0.memory
    }

    /// the number of active CPUs
    pub fn get_cpus(&self) -> i32 {
        (self.0).0.cpus
    }

    /// number of cores per socket, total number of processors in case of unusual NUMA topology
    pub fn get_cores(&self) -> i32 {
        (self.0).0.cores
    }

    /// number of CPU sockets per node if nodes > 1, 1 in case of unusual NUMA topology
    pub fn get_sockets(&self) -> i32 {
        (self.0).0.sockets
    }

    /// the number of NUMA cell, 1 for unusual NUMA topologies or uniform memory access;
    /// check capabilities XML for the actual NUMA topology
    pub fn get_nodes(&self) -> i32 {
        (self.0).0.nodes
    }
}

/// Auth list request must be the first request
req!(AuthListRequest);
resp!(AuthListResponse: generated::remote_auth_list_ret);
rpc!(remote_procedure::REMOTE_PROC_AUTH_LIST, AuthListRequest => AuthListResponse);

/// Connect open request
use generated::remote_connect_open_args;
req!(ConnectOpenRequest: remote_connect_open_args {
     name => Some(generated::remote_nonnull_string("qemu:///system".to_string())),
     flags => 0
});
resp!(ConnectOpenResponse);
rpc!(remote_procedure::REMOTE_PROC_CONNECT_OPEN, ConnectOpenRequest => ConnectOpenResponse);

/// Version request
req!(GetLibVersionRequest);
resp!(GetLibVersionResponse: generated::remote_connect_get_lib_version_ret);
rpc!(remote_procedure::REMOTE_PROC_CONNECT_GET_LIB_VERSION, GetLibVersionRequest => GetLibVersionResponse);

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
rpc!(remote_procedure::REMOTE_PROC_CONNECT_LIST_DEFINED_DOMAINS, ListDefinedDomainsRequest => ListDefinedDomainsResponse);

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
rpc!(remote_procedure::REMOTE_PROC_DOMAIN_DEFINE_XML_FLAGS, DomainDefineXMLRequest => DomainDefineXMLResponse);

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
rpc!(remote_procedure::REMOTE_PROC_DOMAIN_SHUTDOWN, DomainShutdownRequest => DomainShutdownResponse);

use generated::remote_domain_reboot_args;
req!(DomainRebootRequest: remote_domain_reboot_args {
    dom: &Domain => dom.0.to_owned(),
    flags: u32 => flags
});

resp!(DomainRebootResponse);
rpc!(remote_procedure::REMOTE_PROC_DOMAIN_REBOOT, DomainRebootRequest => DomainRebootResponse);

use generated::remote_domain_reset_args;
req!(DomainResetRequest: remote_domain_reset_args {
    dom: &Domain => dom.0.to_owned(),
    flags: u32 => flags
});

resp!(DomainResetResponse);
rpc!(remote_procedure::REMOTE_PROC_DOMAIN_RESET, DomainResetRequest => DomainResetResponse);

use generated::remote_domain_undefine_flags_args;
req!(DomainUndefineRequest: remote_domain_undefine_flags_args {
    dom: Domain => dom.0,
    flags: u32 => flags
});

resp!(DomainUndefineResponse);
rpc!(remote_procedure::REMOTE_PROC_DOMAIN_UNDEFINE, DomainUndefineRequest => DomainUndefineResponse);

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
rpc!(remote_procedure::REMOTE_PROC_DOMAIN_CREATE_WITH_FLAGS, DomainCreateRequest => DomainCreateResponse);

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
rpc!(remote_procedure::REMOTE_PROC_DOMAIN_DESTROY_FLAGS, DomainDestroyRequest => DomainDestroyResponse);

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
    const PROCEDURE: ::remote_procedure = remote_procedure::REMOTE_PROC_CONNECT_LIST_ALL_DOMAINS;
    type Response = ListAllDomainsResponse;
}

/*
use generated::remote_connect_domain_event_register_any_args;
req!(DomainEventRegisterAnyRequest: remote_connect_domain_event_register_any_args {
    eventID as event: i32
});

resp!(DomainEventRegisterAnyResponse);
rpc!(DomainEventRegisterAnyRequest => DomainEventRegisterAnyResponse);
*/

use generated::remote_connect_domain_event_callback_register_any_args;
req!(DomainEventCallbackRegisterAnyRequest: remote_connect_domain_event_callback_register_any_args {
    eventID as event: i32 => event,
    dom as domain: Option<&Domain> => domain.map(|dom| Box::new(dom.0.clone()))
});

resp!(DomainEventCallbackRegisterAnyResponse: generated::remote_connect_domain_event_callback_register_any_ret);
rpc!(remote_procedure::REMOTE_PROC_CONNECT_DOMAIN_EVENT_CALLBACK_REGISTER_ANY, DomainEventCallbackRegisterAnyRequest => DomainEventCallbackRegisterAnyResponse);

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
rpc!(remote_procedure::REMOTE_PROC_DOMAIN_LOOKUP_BY_UUID, DomainLookupByUuidRequest => DomainLookupByUuidResponse);

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

pub trait DomainEvent where Self: Sized {
    type From: Into<Self> + ::xdr_codec::Unpack<::std::io::Cursor<::bytes::BytesMut>>;
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
pub struct DomainLifecycleEvent {
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

impl DomainEvent for DomainLifecycleEvent {
    type From = generated::remote_domain_event_callback_lifecycle_msg;
}

impl From<generated::remote_domain_event_callback_lifecycle_msg> for DomainLifecycleEvent {
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
        DomainLifecycleEvent { domain, info }
    }
}

#[derive(Debug)]
pub struct DomainRebootEvent {
    pub domain: Domain,
}

impl DomainEvent for DomainRebootEvent {
    type From = generated::remote_domain_event_callback_reboot_msg;
}

impl From<generated::remote_domain_event_callback_reboot_msg> for DomainRebootEvent {
    fn from(ev: generated::remote_domain_event_callback_reboot_msg) -> Self {
        let domain = Domain(ev.msg.dom);
        DomainRebootEvent { domain }
    }
}

// http://libvirt.org/html/libvirt-libvirt-domain.html#virDomainEventID
#[derive(Debug,Copy,Clone)]
pub enum DomainEventId {
    Lifecycle,
    Reboot,
    RtcChange,
    Watchdog,
    IoError,
    Graphics,
    IoErrorReason,
    ControlError,
    BlockJob,
    DiskChange,
    TrayChange,
    PmWakeup,
    PmSuspend,
    BalloonChange,
    PmSuspendDisk,
    DeviceRemoved,
    BlockJob2,
    Tunable,
    AgentLifecycle,
    DeviceAdded,
    MigrationIteration,
    JobCompleted,
    DeviceRemovalFailed,
    MetadataChanged,
    BlockThreshold,
}

impl DomainEventId {
    pub fn get_method(&self) -> remote_procedure {
        use self::DomainEventId::*;
        use remote_procedure::*;
        match *self {
            Lifecycle => REMOTE_PROC_DOMAIN_EVENT_CALLBACK_LIFECYCLE,
            Reboot => REMOTE_PROC_DOMAIN_EVENT_CALLBACK_REBOOT,
            _ => unimplemented!(), /* sorry */
        }
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

rpc!(remote_procedure::REMOTE_PROC_CONNECT_LIST_ALL_STORAGE_POOLS, ListAllStoragePoolsRequest => ListAllStoragePoolsResponse);

use generated::remote_storage_pool_define_xml_args;
req!(StoragePoolDefineXmlRequest: remote_storage_pool_define_xml_args {
    xml: &str => generated::remote_nonnull_string(xml.to_string()),
    flags: u32 => flags
});

resp!(StoragePoolDefineXmlResponse: generated::remote_storage_pool_define_xml_ret);
rpc!(remote_procedure::REMOTE_PROC_STORAGE_POOL_DEFINE_XML, StoragePoolDefineXmlRequest => StoragePoolDefineXmlResponse);

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
rpc!(remote_procedure::REMOTE_PROC_STORAGE_POOL_LOOKUP_BY_UUID, StoragePoolLookupByUuidRequest => StoragePoolLookupByUuidResponse);

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
rpc!(remote_procedure::REMOTE_PROC_STORAGE_POOL_LOOKUP_BY_NAME, StoragePoolLookupByNameRequest => StoragePoolLookupByNameResponse);

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
rpc!(remote_procedure::REMOTE_PROC_STORAGE_POOL_CREATE, StoragePoolCreateRequest => StoragePoolCreateResponse);

use generated::remote_storage_pool_destroy_args;
req!(StoragePoolDestroyRequest: remote_storage_pool_destroy_args {
    pool: &StoragePool => pool.0.clone()
});
resp!(StoragePoolDestroyResponse);
rpc!(remote_procedure::REMOTE_PROC_STORAGE_POOL_DESTROY, StoragePoolDestroyRequest => StoragePoolDestroyResponse);

use generated::remote_storage_pool_undefine_args;
req!(StoragePoolUndefineRequest: remote_storage_pool_undefine_args {
    pool: StoragePool => pool.0
});
resp!(StoragePoolUndefineResponse);
rpc!(remote_procedure::REMOTE_PROC_STORAGE_POOL_UNDEFINE, StoragePoolUndefineRequest => StoragePoolUndefineResponse);

use generated::remote_storage_pool_get_info_args;
req!(StoragePoolGetInfoRequest: remote_storage_pool_get_info_args {
    pool: &StoragePool => pool.0.clone()
});
resp!(StoragePoolGetInfoResponse: generated::remote_storage_pool_get_info_ret);
rpc!(remote_procedure::REMOTE_PROC_STORAGE_POOL_GET_INFO, StoragePoolGetInfoRequest => StoragePoolGetInfoResponse);

#[derive(Debug)]
pub struct StoragePoolInfo(StoragePoolGetInfoResponse);

impl From<StoragePoolGetInfoResponse> for StoragePoolInfo {
    fn from(v: StoragePoolGetInfoResponse) -> Self {
        StoragePoolInfo(v)
    }
}

impl StoragePoolInfo {
    pub fn get_capacity(&self) -> u64 {
        (self.0).0.capacity
    }

    pub fn get_allocation(&self) -> u64 {
        (self.0).0.allocation
    }

    pub fn get_available(&self) -> u64 {
        (self.0).0.available
    }
}

use generated::remote_storage_pool_list_volumes_args;
req!(StoragePoolListVolumesRequest: remote_storage_pool_list_volumes_args {
    pool: &StoragePool => pool.0.clone(),
    maxnames: i32 => maxnames
});
resp!(StoragePoolListVolumesResponse: generated::remote_storage_pool_list_volumes_ret);
rpc!(remote_procedure::REMOTE_PROC_STORAGE_POOL_LIST_VOLUMES, StoragePoolListVolumesRequest => StoragePoolListVolumesResponse);

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
rpc!(remote_procedure::REMOTE_PROC_STORAGE_POOL_LIST_ALL_VOLUMES, StoragePoolListAllVolumesRequest => StoragePoolListAllVolumesResponse);

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
rpc!(remote_procedure::REMOTE_PROC_STORAGE_VOL_CREATE_XML, StorageVolCreateXmlRequest => StorageVolCreateXmlResponse);

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
rpc!(remote_procedure::REMOTE_PROC_STORAGE_VOL_CREATE_XML_FROM, StorageVolCreateXmlFromRequest => StorageVolCreateXmlFromResponse);

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
rpc!(remote_procedure::REMOTE_PROC_STORAGE_VOL_DELETE, StorageVolDeleteRequest => StorageVolDeleteResponse);

use generated::remote_storage_vol_wipe_args;
req!(StorageVolWipeRequest: remote_storage_vol_wipe_args {
    vol: &Volume => vol.0.clone(),
    flags: u32 => flags
});
resp!(StorageVolWipeResponse);
rpc!(remote_procedure::REMOTE_PROC_STORAGE_VOL_WIPE, StorageVolWipeRequest => StorageVolWipeResponse);

use generated::remote_storage_vol_lookup_by_name_args;
req!(StorageVolLookupByNameRequest: remote_storage_vol_lookup_by_name_args {
    pool: &StoragePool => pool.0.clone(),
    name: &str => generated::remote_nonnull_string(name.to_owned())
});
resp!(StorageVolLookupByNameResponse: generated::remote_storage_vol_lookup_by_name_ret);
rpc!(remote_procedure::REMOTE_PROC_STORAGE_VOL_LOOKUP_BY_NAME, StorageVolLookupByNameRequest => StorageVolLookupByNameResponse);

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
rpc!(remote_procedure::REMOTE_PROC_STORAGE_VOL_RESIZE, StorageVolResizeRequest => StorageVolResizeResponse);

use generated::remote_storage_vol_get_info_args;
req!(StorageVolGetInfoRequest: remote_storage_vol_get_info_args {
    vol: &Volume => vol.0.clone()
});
resp!(StorageVolGetInfoResponse: generated::remote_storage_vol_get_info_ret);
rpc!(remote_procedure::REMOTE_PROC_STORAGE_VOL_GET_INFO, StorageVolGetInfoRequest => StorageVolGetInfoResponse);

impl Into<VolumeInfo> for StorageVolGetInfoResponse {
    fn into(self) -> VolumeInfo {
        VolumeInfo(self.0)
    }
}

#[derive(Debug)]
pub struct VolumeInfo(generated::remote_storage_vol_get_info_ret);

impl VolumeInfo {
    pub fn get_capacity(&self) -> u64 {
        (self.0).capacity
    }

    pub fn get_allocation(&self) -> u64 {
        (self.0).allocation
    }
}

use generated::remote_domain_screenshot_args;
req!(DomainScreenshotRequest: remote_domain_screenshot_args {
    dom: &Domain => dom.0.clone(),
    screen: u32 => screen,
    flags: u32 => flags
});
resp!(DomainScreenshotResponse: generated::remote_domain_screenshot_ret);
rpc!(remote_procedure::REMOTE_PROC_DOMAIN_SCREENSHOT, DomainScreenshotRequest => DomainScreenshotResponse);

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
rpc!(remote_procedure::REMOTE_PROC_STORAGE_VOL_DOWNLOAD, StorageVolDownloadRequest => StorageVolDownloadResponse);

use generated::remote_storage_vol_upload_args;
req!(StorageVolUploadRequest: remote_storage_vol_upload_args {
    vol: &Volume => vol.0.clone(),
    offset: u64 => offset,
    length: u64 => length,
    flags: u32 => flags
});
resp!(StorageVolUploadResponse);
rpc!(remote_procedure::REMOTE_PROC_STORAGE_VOL_UPLOAD, StorageVolUploadRequest => StorageVolUploadResponse);

use generated::remote_domain_get_info_args;
req!(DomainGetInfoRequest: remote_domain_get_info_args {
    dom: &Domain => dom.0.clone()
});
resp!(DomainGetInfoResponse: generated::remote_domain_get_info_ret);
rpc!(remote_procedure::REMOTE_PROC_DOMAIN_GET_INFO, DomainGetInfoRequest => DomainGetInfoResponse);

use generated::remote_domain_attach_device_flags_args;
req!(DomainAttachDeviceRequest: remote_domain_attach_device_flags_args {
    dom: &Domain => dom.0.clone(),
    xml: &str => generated::remote_nonnull_string(xml.to_owned()),
    flags: DomainModificationImpact::DomainModificationImpact => flags.bits()
});
resp!(DomainAttachDeviceResponse);
rpc!(remote_procedure::REMOTE_PROC_DOMAIN_ATTACH_DEVICE_FLAGS, DomainAttachDeviceRequest => DomainAttachDeviceResponse);

use generated::remote_domain_detach_device_flags_args;
req!(DomainDetachDeviceRequest: remote_domain_detach_device_flags_args {
    dom: &Domain => dom.0.clone(),
    xml: &str => generated::remote_nonnull_string(xml.to_owned()),
    flags: DomainModificationImpact::DomainModificationImpact => flags.bits()
});
resp!(DomainDetachDeviceResponse);
rpc!(remote_procedure::REMOTE_PROC_DOMAIN_DETACH_DEVICE_FLAGS, DomainDetachDeviceRequest => DomainDetachDeviceResponse);

use generated::remote_domain_update_device_flags_args;
req!(DomainUpdateDeviceRequest: remote_domain_update_device_flags_args {
    dom: &Domain => dom.0.clone(),
    xml: &str => generated::remote_nonnull_string(xml.to_owned()),
    flags: DomainModificationImpact::DomainModificationImpact => flags.bits()
});
resp!(DomainUpdateDeviceResponse);
rpc!(remote_procedure::REMOTE_PROC_DOMAIN_UPDATE_DEVICE_FLAGS, DomainUpdateDeviceRequest => DomainUpdateDeviceResponse);

use generated::remote_domain_set_memory_flags_args;
req!(DomainSetMemoryRequest: remote_domain_set_memory_flags_args {
    dom: &Domain => dom.0.clone(),
    memory: u64 => memory,
    flags: DomainModificationImpact::MemoryModificationImpact => flags.bits()
});
resp!(DomainSetMemoryResponse);
rpc!(remote_procedure::REMOTE_PROC_DOMAIN_SET_MEMORY_FLAGS, DomainSetMemoryRequest => DomainSetMemoryResponse);

/*
use generated::remote_domain_get_max_memory_args;
req!(DomainGetMaxMemoryRequest: remote_domain_get_max_memory_args {
    dom: &Domain => dom.0.clone()
});
resp!(DomainGetMaxMemoryResponse: generated::remote_domain_get_max_memory_ret);
rpc!(DomainGetMaxMemoryRequest => DomainGetMaxMemoryResponse);
*/

use generated::remote_domain_get_memory_parameters_args;
req!(DomainGetMemoryParametersRequest: remote_domain_get_memory_parameters_args {
    dom: &Domain => dom.0.clone(),
    nparams: u32 => nparams as i32, 
    flags: DomainModificationImpact::DomainModificationImpact => flags.bits()
});
resp!(DomainGetMemoryParametersResponse: generated::remote_domain_get_memory_parameters_ret);
rpc!(remote_procedure::REMOTE_PROC_DOMAIN_GET_MEMORY_PARAMETERS, DomainGetMemoryParametersRequest => DomainGetMemoryParametersResponse);

impl DomainGetMemoryParametersResponse {
    pub fn count(&self) -> u32 {
        self.0.nparams as u32
    }

    pub fn parameters(self) -> Vec<TypedParam> {
        self.0.params.into_iter().map(TypedParam::from).collect()
    }
}

use generated::remote_domain_set_vcpus_flags_args;
req!(DomainSetVcpusRequest: remote_domain_set_vcpus_flags_args {
    dom: &Domain => dom.0.clone(),
    nvcpus: u32 => nvcpus,
    flags: DomainModificationImpact::VcpuModificationImpact => flags.bits()
});
resp!(DomainSetVcpusResponse);
rpc!(remote_procedure::REMOTE_PROC_DOMAIN_SET_VCPUS_FLAGS, DomainSetVcpusRequest => DomainSetVcpusResponse);

use generated::remote_domain_get_vcpus_flags_args;
req!(DomainGetVcpusRequest: remote_domain_get_vcpus_flags_args {
    dom: &Domain => dom.0.clone(),
    flags: DomainModificationImpact::VcpuModificationImpact => flags.bits()
});
resp!(DomainGetVcpusResponse: generated::remote_domain_get_vcpus_flags_ret);
rpc!(remote_procedure::REMOTE_PROC_DOMAIN_GET_VCPUS_FLAGS, DomainGetVcpusRequest => DomainGetVcpusResponse);

impl Into<u32> for DomainGetVcpusResponse {
    fn into(self) -> u32 {
        (self.0).num as u32
    }
}

use generated::remote_domain_get_autostart_args;
req!(DomainGetAutoStartRequest: remote_domain_get_autostart_args {
    dom: &Domain => dom.0.clone()
});
resp!(DomainGetAutoStartResponse: generated::remote_domain_get_autostart_ret);
rpc!(remote_procedure::REMOTE_PROC_DOMAIN_GET_AUTOSTART, DomainGetAutoStartRequest => DomainGetAutoStartResponse);

impl Into<bool> for DomainGetAutoStartResponse {
    fn into(self) -> bool {
        (self.0).autostart == 1
    }
}

use generated::remote_domain_set_autostart_args;
req!(DomainSetAutoStartRequest: remote_domain_set_autostart_args {
    dom: &Domain => dom.0.clone(),
    autostart: bool => if autostart { 1 } else { 0 }
});
resp!(DomainSetAutoStartResponse);
rpc!(remote_procedure::REMOTE_PROC_DOMAIN_SET_AUTOSTART, DomainSetAutoStartRequest => DomainSetAutoStartResponse);

use generated::remote_domain_send_key_args;
req!(DomainSendKeyRequest: remote_domain_send_key_args {
    dom: &Domain => dom.0.clone(),
    codeset: u32 => codeset,
    holdtime: u32 => holdtime,
    keycodes: Vec<u32> => keycodes,
    flags: u32 => flags
});
resp!(DomainSendKeyResponse);
rpc!(remote_procedure::REMOTE_PROC_DOMAIN_SEND_KEY, DomainSendKeyRequest => DomainSendKeyResponse);

use generated::remote_domain_get_xml_desc_args;
req!(DomainGetXmlDescRequest: remote_domain_get_xml_desc_args {
    dom: &Domain => dom.0.clone(),
    flags: DomainXmlFlags::DomainXmlFlags => flags.bits()
});
resp!(DomainGetXmlDescResponse: generated::remote_domain_get_xml_desc_ret);
rpc!(remote_procedure::REMOTE_PROC_DOMAIN_GET_XML_DESC, DomainGetXmlDescRequest => DomainGetXmlDescResponse);

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

    bitflags! {
        pub flags MemoryModificationImpact: u32 {
            const MEM_CURRENT = 0, // AFFECT_CURRENT, // as u32,

            const MEM_LIVE = 1, // AFFECT_LIVE as u32,

            const MEM_CONFIG = 2, // AFFECT_CONFIG as u32,

            /// affect max. value
            const MEM_MAXIMUM = 4,
        }
    }

    bitflags! {
        pub flags VcpuModificationImpact: u32 {
            const VCPU_CURRENT = 0, // AFFECT_CURRENT, // as u32,

            const VCPU_LIVE = 1, // AFFECT_LIVE as u32,

            const VCPU_CONFIG = 2, // AFFECT_CONFIG as u32,

            /// affect max. value
            const VCPU_MAXIMUM = 4,

            // modify state of the cpu in the guest
            const VCPU_GUEST = 8,

            const VCPU_HOTPLUGGABLE = 16,
        }
    }
}

#[allow(non_snake_case)]
pub mod DomainMigrateFlags {
    bitflags! {
        pub flags DomainMigrateFlags: u32 {
            /// Do not pause the domain during migration. The domain's memory will
            /// be transferred to the destination host while the domain is running.
            /// The migration may never converge if the domain is changing its memory
            /// faster then it can be transferred. The domain can be manually paused
            /// anytime during migration using virDomainSuspend.
            const VIR_MIGRATE_LIVE	=	1,
            /// Tell the source libvirtd to connect directly to the destination host.
            /// Without this flag the client (e.g., virsh) connects to both hosts and controls the migration process.
            /// In peer-to-peer mode, the source libvirtd controls the migration by calling the destination daemon directly.
            const VIR_MIGRATE_PEER2PEER	=	2,
            /// Tunnel migration data over libvirtd connection. Without this flag the source hypervisor sends migration data
            /// directly to the destination hypervisor. This flag can only be used when VIR_MIGRATE_PEER2PEER is set as well.
            /// Note the less-common spelling that we're stuck with: VIR_MIGRATE_TUNNELLED should be VIR_MIGRATE_TUNNELED.
            const VIR_MIGRATE_TUNNELLED	=	4,
            /// Define the domain as persistent on the destination host after successful migration.
            /// If the domain was persistent on the source host and VIR_MIGRATE_UNDEFINE_SOURCE is not used, it will end up persistent on both hosts.
            const VIR_MIGRATE_PERSIST_DEST	=	8,
            /// Undefine the domain on the source host once migration successfully finishes.
            const VIR_MIGRATE_UNDEFINE_SOURCE	=	16,
            /// Leave the domain suspended on the destination host. virDomainResume (on the virDomainPtr returned by the migration API)
            /// has to be called explicitly to resume domain's virtual CPUs.
            const VIR_MIGRATE_PAUSED	=	32,
            /// Migrate full disk images in addition to domain's memory.
            /// By default only non-shared non-readonly disk images are transferred.
            /// The VIR_MIGRATE_PARAM_MIGRATE_DISKS parameter can be used to specify which disks should be migrated.
            /// This flag and VIR_MIGRATE_NON_SHARED_INC are mutually exclusive.
            const VIR_MIGRATE_NON_SHARED_DISK	=	64,
            /// Migrate disk images in addition to domain's memory.
            /// This is similar to VIR_MIGRATE_NON_SHARED_DISK, but only the top level of each disk's backing chain is copied.
            /// That is, the rest of the backing chain is expected to be present on the destination and to be exactly the
            /// same as on the source host. This flag and VIR_MIGRATE_NON_SHARED_DISK are mutually exclusive.
            const VIR_MIGRATE_NON_SHARED_INC	=	128,
            /// Protect against domain configuration changes during the migration process.
            /// This flag is used automatically when both sides support it.
            /// Explicitly setting this flag will cause migration to fail if either the source or the destination does not support it.
            const VIR_MIGRATE_CHANGE_PROTECTION	=	256,
            /// Force migration even if it is considered unsafe.
            /// In some cases libvirt may refuse to migrate the domain because doing so may lead to potential problems
            /// such as data corruption, and thus the migration is considered unsafe.
            /// For a QEMU domain this may happen if the domain uses disks without explicitly setting cache mode to "none".
            /// Migrating such domains is unsafe unless the disk images are stored on coherent clustered filesystem, such as GFS2 or GPFS.
            const VIR_MIGRATE_UNSAFE	=	512,
            /// Migrate a domain definition without starting the domain on the destination and without stopping it on the source host.
            /// Offline migration requires VIR_MIGRATE_PERSIST_DEST to be set. Offline migration may not copy disk storage or any other
            /// file based storage (such as UEFI variables).
            const VIR_MIGRATE_OFFLINE	=	1024,
            /// Compress migration data. The compression methods can be specified using VIR_MIGRATE_PARAM_COMPRESSION.
            /// A hypervisor default method will be used if this parameter is omitted.
            /// Individual compression methods can be tuned via their specific VIR_MIGRATE_PARAM_COMPRESSION_* parameters.
            const VIR_MIGRATE_COMPRESSED	=	2048,
            /// Cancel migration if a soft error (such as I/O error) happens during migration.
            const VIR_MIGRATE_ABORT_ON_ERROR	=	4096,
            /// Enable algorithms that ensure a live migration will eventually converge.
            /// This usually means the domain will be slowed down to make sure it does not change its memory faster
            /// than a hypervisor can transfer the changed memory to the destination host.
            /// VIR_MIGRATE_PARAM_AUTO_CONVERGE_* parameters can be used to tune the algorithm.
            const VIR_MIGRATE_AUTO_CONVERGE	=	8192,
            /// This flag can be used with RDMA migration (i.e., when VIR_MIGRATE_PARAM_URI starts with "rdma://") to
            /// tell the hypervisor to pin all domain's memory at once before migration starts rather then letting it
            /// pin memory pages as needed. This means that all memory pages belonging to the domain will be locked in
            /// host's memory and the host will not be allowed to swap them out.
            /// For QEMU/KVM this requires hard_limit memory tuning element (in the domain XML) to be used and set to
            /// the maximum memory configured for the domain plus any memory consumed by the QEMU process itself.
            /// Beware of setting the memory limit too high (and thus allowing the domain to lock most of the host's memory).
            /// Doing so may be dangerous to both the domain and the host itself since the host's kernel may run out of memory.
            const VIR_MIGRATE_RDMA_PIN_ALL	=	16384,
            /// Setting the VIR_MIGRATE_POSTCOPY flag tells libvirt to enable post-copy migration.
            /// However, the migration will start normally and virDomainMigrateStartPostCopy needs to be called to switch it into the post-copy mode.
            /// See virDomainMigrateStartPostCopy for more details.
            const VIR_MIGRATE_POSTCOPY	=	32768,
            /// Setting the VIR_MIGRATE_TLS flag will cause the migration to attempt to use the TLS environment configured
            /// by the hypervisor in order to perform the migration. If incorrectly configured on either source or destination, the migration will fail.
            const VIR_MIGRATE_TLS	=	65536,
        }
    }
}

use generated::remote_domain_migrate_perform3_params_args;
req!(MigratePerformRequest: remote_domain_migrate_perform3_params_args {
    dom: &Domain => dom.0.clone(),
    dconnuri: Option<&str> => dconnuri.map(|uri| generated::remote_nonnull_string(uri.to_string())),
    params: Vec<MigrationParam> => params.into_iter().map(|mp| {
        let tp: TypedParam = mp.into();
        tp.into()
    }).collect(),
    cookie_in: Vec<u8> => cookie_in,
    flags: DomainMigrateFlags::DomainMigrateFlags => flags.bits()
});
resp!(MigratePerformResponse: generated::remote_domain_migrate_perform3_params_ret);
rpc!(remote_procedure::REMOTE_PROC_DOMAIN_MIGRATE_PERFORM3_PARAMS, MigratePerformRequest => MigratePerformResponse);

/*
use generated::remote_domain_migrate_begin3_params_args;
req!(MigrateBeginRequest: remote_domain_migrate_begin3_params_args {
    dom: &Domain => dom.0.clone(),
    params: Vec<MigrationParam> => params.into_iter().map(|mp| {
        let tp: TypedParam = mp.into();
        tp.into()
    }).collect(),
    flags: DomainMigrateFlags::DomainMigrateFlags => flags.bits()
});
resp!(MigrateBeginResponse: generated::remote_domain_migrate_begin3_params_ret);
rpc!(MigrateBeginRequest => MigrateBeginResponse);
*/
#[derive(Debug)]
pub enum MigrationParam {
    /// URI to use for initiating domain migration. It takes a hypervisor specific format. The
    /// uri_transports element of the hypervisor capabilities XML includes details
    /// of the supported URI schemes. When omitted libvirt will auto-generate
    /// suitable default URI. It is typically only necessary to specify this URI if
    /// the destination host has multiple interfaces and a specific interface is
    /// required to transmit migration data.
    /// 
    /// This filed may not be used when VIR_MIGRATE_TUNNELLED flag is set.
    Uri(String),
    /// the name to be used for the domain on the
    /// destination host. Omitting this parameter keeps
    /// the domain name the same. This field is only allowed to be used with
    /// hypervisors that support domain renaming during migration.
    DestinationName(String),
    /// the new configuration to be used for the
    /// domain on the destination host. The configuration
    /// must include an identical set of virtual devices, to ensure a stable guest
    /// ABI across migration. Only parameters related to host side configuration
    /// can be changed in the XML. Hypervisors which support this field will forbid
    /// migration if the provided XML would cause a change in the guest ABI. This
    /// field cannot be used to rename the domain during migration (use
    /// VIR_MIGRATE_PARAM_DEST_NAME field for that purpose). Domain name in the
    /// destination XML must match the original domain name.
    ///
    /// Omitting this parameter keeps the original domain configuration. Using this
    /// field with hypervisors that do not support changing domain configuration
    /// during migration will result in a failure.
    DestinationXml(String),
    /// the new persistent configuration to be used
    /// for the domain on the destination host.
    /// This field cannot be used to rename the domain during migration (use
    /// VIR_MIGRATE_PARAM_DEST_NAME field for that purpose). Domain name in the
    /// destination XML must match the original domain name.
    ///
    /// Omitting this parameter keeps the original domain persistent configuration.
    /// Using this field with hypervisors that do not support changing domain
    /// configuration during migration will result in a failure.
    PersistentXml(String),
    ///   the maximum bandwidth (in MiB/s) that will
    /// be used for migration. If set to 0 or omitted,
    /// libvirt will choose a suitable default. Some hypervisors do not support this
    /// feature and will return an error if this field is used and is not 0.
    Bandwidth(u64),
    /// URI to use for migrating client's connection
    /// to domain's graphical console. If specified, the
    /// client will be asked to automatically reconnect using these parameters
    /// instead of the automatically computed ones. This can be useful if, e.g., the
    /// client does not have a direct access to the network virtualization hosts are
    /// connected to and needs to connect through a proxy. The URI is formed as
    /// follows: protocol://hostname[:port]/[?parameters]
    /// where protocol is either "spice" or "vnc" and parameters is a list of
    /// protocol specific parameters separated by '&'. Currently recognized
    /// parameters are "tlsPort" and "tlsSubject". For example, spice://target.host.com:1234/?tlsPort=4567
    GraphicsUri(String),
    /// The listen address that hypervisor on the
    /// destination side should bind to for incoming migration. Both IPv4 and IPv6
    /// addresses are accepted as well as hostnames (the resolving is done on
    /// destination). Some hypervisors do not support this feature and will return
    /// an error if this field is used.
    ListenAddress(String),
    /// The multiple values that list
    /// the block devices to be migrated. At the moment this is only supported
    /// by the QEMU driver but not for the tunnelled migration.
    MigrateDisks(String),
    /// virDomainMigrate* params field: port that destination server should use
    /// for incoming disks migration. If set to 0 or
    /// omitted, libvirt will choose a suitable default. At the moment this is only
    /// supported by the QEMU driver.
    DisksPort(i32),
    /// virDomainMigrate* params multiple field: name of the method used to
    /// compress migration traffic. Supported compression methods: xbzrle, mt.
    /// The parameter may be specified multiple times if more than one method
    /// should be used.
    Compression(String),
    /// the level of compression for multithread
    /// compression. Accepted values are in range 0-9.
    /// 0 is no compression, 1 is maximum speed and 9 is maximum compression.
    CompressionLevel(i32),
    /// the number of compression threads for
    /// multithread compression
    CompressionThreads(i32),
    /// the number of decompression threads for
    /// multithread compression
    DecompressionThreads(i32),
    /// the size of page cache for xbzrle compression
    CompressionXbzrleCache(u64),
    /// the initial percentage guest CPUs are
    /// throttled to when auto-convergence decides migration is not converging.
    AutoConvergeInitial(i32),
    /// the increment added to
    /// VIR_MIGRATE_PARAM_AUTO_CONVERGE_INITIAL whenever the hypervisor decides
    /// the current rate is not enough to ensure convergence of the migration.
    AutoConvergeIncrement(i32),
}

impl Into<TypedParam> for MigrationParam {
    fn into(self) -> TypedParam {
        match self {
            MigrationParam::Uri(ref s) => TypedParam::string("migrate_uri", s),
            MigrationParam::DestinationName(ref s) => TypedParam::string("destination_name", s),
            MigrationParam::DestinationXml(ref s) => TypedParam::string("destination_xml", s),
            MigrationParam::PersistentXml(ref s) => TypedParam::string("persistent_xml", s),
            MigrationParam::Bandwidth(ref i) => TypedParam::ulonglong("bandwidth", *i),
            MigrationParam::GraphicsUri(ref s) => TypedParam::string("graphics_uri", s),
            MigrationParam::ListenAddress(ref s) => TypedParam::string("listen_address", s),
            MigrationParam::MigrateDisks(ref s) => TypedParam::string("migrate_disks", s),
            MigrationParam::DisksPort(ref i) => TypedParam::int("disks_port", *i),
            MigrationParam::Compression(ref s) => TypedParam::string("compression", s),
            MigrationParam::CompressionLevel(ref i) => TypedParam::int("compression.mt.level", *i),
            MigrationParam::CompressionThreads(ref i) => TypedParam::int("compression.mt.threads", *i),
            MigrationParam::DecompressionThreads(ref i) => TypedParam::int("compression.mt.dthreads", *i),
            MigrationParam::CompressionXbzrleCache(ref i) => TypedParam::ulonglong("compression.xbzrle.cache", *i),
            MigrationParam::AutoConvergeInitial(ref i) => TypedParam::int("auto_converge.initial", *i),
            MigrationParam::AutoConvergeIncrement(ref i) => TypedParam::int("auto_converge.increment", *i),
        }
    }
}

#[derive(Debug)]
pub struct TypedParam(generated::remote_typed_param);

impl TypedParam {
    fn string(name: &str, value: &str) -> Self {
        TypedParam(generated::remote_typed_param {
            field: generated::remote_nonnull_string(name.to_string()),
            value: generated::remote_typed_param_value::Const7(generated::remote_nonnull_string(value.to_string())),
        })
    }

    fn ulonglong(name: &str, value: u64) -> Self {
        TypedParam(generated::remote_typed_param {
            field: generated::remote_nonnull_string(name.to_string()),
            value: generated::remote_typed_param_value::Const4(value),
        })
    }

    fn int(name: &str, value: i32) -> Self {
        TypedParam(generated::remote_typed_param {
            field: generated::remote_nonnull_string(name.to_string()),
            value: generated::remote_typed_param_value::Const1(value),
        })
    }
    /* TODO: more */
}

impl Into<generated::remote_typed_param> for TypedParam {
    fn into(self) -> generated::remote_typed_param {
        self.0
    }
}

impl From<generated::remote_typed_param> for TypedParam {
    fn from(p: generated::remote_typed_param) -> Self {
        TypedParam(p)
    }
}

#[derive(Debug)]
pub struct DomainInfo(DomainGetInfoResponse);

impl DomainInfo {
    pub fn get_state(&self) -> DomainState {
        DomainState::from((self.0).0.state as u8)
    }

    pub fn get_max_mem(&self) -> u64 {
        (self.0).0.maxMem
    }

    pub fn get_num_cpus(&self) -> u32 {
        (self.0).0.nrVirtCpu as u32
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
