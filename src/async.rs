//! This module provides tokio based async interface to libvirt API
//!  
//! # Examples
//!
//! ## Connect to local libvirtd and get list of domains
//!
//! ```
//! extern crate tokio_core;
//! extern crate libvirt_rpc;
//! extern crate futures;
//!
//! use ::tokio_core::reactor::Core;
//! use libvirt_rpc::async::Client;
//! use libvirt_rpc::request;
//! use futures::Future;
//!
//! fn main() {
//!     let mut core = Core::new().unwrap();
//!     let handle = core.handle(); 
//!     let client = Client::connect("/var/run/libvirt/libvirt-sock", &handle).unwrap();
//!     let result = core.run({
//!         client.auth()
//!           .and_then(|_| client.open())
//!           .and_then(|_| client.domain().list(request::ListAllDomainsFlags::DOMAINS_ACTIVE | request::ListAllDomainsFlags::DOMAINS_INACTIVE))
//!     }).unwrap();
//!     println!("{:?}", result);
//! }
//! ```
//!
use std::io::Cursor;
use std::path::Path;
use std::collections::HashMap;
use std::sync::{Arc,Mutex};
use ::xdr_codec::{Pack,Unpack};
use ::bytes::{BufMut, BytesMut};
use ::tokio_proto::multiplex::{self};
use ::tokio_service::Service;
use ::request;
use ::LibvirtError;
use ::futures::{Future, future};
use ::futures::sync::mpsc::{Sender,Receiver};
use ::proto::{LibvirtProto, LibvirtRequest, LibvirtResponse};
pub use ::proto::{LibvirtSink, LibvirtStream, EventStream};

/// Libvirt client
#[derive(Clone)]
pub struct Client {
    events: Arc<Mutex<HashMap<i32, ::futures::sync::mpsc::Sender<::request::DomainEvent>>>>,
    inner: Arc<Mutex<multiplex::ClientService<::tokio_uds::UnixStream, LibvirtProto>>>,
}

impl Client {
    /// opens libvirt connection over unix socket
    pub fn connect<P: AsRef<Path>>(path: P, handle: &::tokio_core::reactor::Handle) -> Result<Client, ::std::io::Error> {
        use ::tokio_uds_proto::UnixClient;
        let events = Arc::new(Mutex::new(HashMap::new()));
        let proto = LibvirtProto::new(events.clone());
        UnixClient::new(proto)
                .connect(path, handle)
                .map(|inner| Client {
                     inner: Arc::new(Mutex::new(inner)),
                     events: events.clone(),
                })
    }

    fn pack<P: Pack<::bytes::Writer<::bytes::BytesMut>>>(procedure: request::remote_procedure,
                     payload: P, stream: Option<Sender<LibvirtResponse>>, sink: Option<Receiver<BytesMut>>) -> Result<LibvirtRequest, ::xdr_codec::Error> {
        let buf = BytesMut::with_capacity(1024);
        let buf = {
            let mut writer = buf.writer();
            try!(payload.pack(&mut writer));
            writer.into_inner()
        };
        let req = LibvirtRequest {
            stream: stream,
            sink: sink,
            header: request::virNetMessageHeader {
                proc_: procedure as i32,
                ..Default::default()
            },
            payload: buf,
        };
        Ok(req)
    }

    fn handle_response<'a, P: Unpack<Cursor<::bytes::BytesMut>>>(resp: LibvirtResponse) -> Result<P, LibvirtError> {
        let mut reader = Cursor::new(resp.payload);
        if resp.header.status == request::virNetMessageStatus::VIR_NET_OK {
            let (pkt, _) = try!(P::unpack(&mut reader));
            Ok(pkt)
        } else {
            let (err, _) = try!(request::virNetMessageError::unpack(&mut reader));
            Err(err.into())
        }
    }

    fn request<P>(&self, procedure: request::remote_procedure, payload: P) ->
     ::futures::BoxFuture<<P as request::LibvirtRpc<Cursor<::bytes::BytesMut>>>::Response, LibvirtError>
        where P: Pack<::bytes::Writer<::bytes::BytesMut>> + request::LibvirtRpc<Cursor<::bytes::BytesMut>>,
        <P as request::LibvirtRpc<Cursor<::bytes::BytesMut>>>::Response: 'static
    {
        self.request_stream(procedure, payload, None)
    }

    fn request_stream<P>(&self, procedure: request::remote_procedure, payload: P, stream: Option<Sender<LibvirtResponse>>) ->
     ::futures::BoxFuture<<P as request::LibvirtRpc<Cursor<::bytes::BytesMut>>>::Response, LibvirtError>
        where P: Pack<::bytes::Writer<::bytes::BytesMut>> + request::LibvirtRpc<Cursor<::bytes::BytesMut>>,
        <P as request::LibvirtRpc<Cursor<::bytes::BytesMut>>>::Response: 'static
    {
        self.request_sink_stream(procedure, payload, stream, None)
    }

    fn request_sink<P>(&self, procedure: request::remote_procedure, payload: P, sink: Option<Receiver<BytesMut>>) ->
     ::futures::BoxFuture<<P as request::LibvirtRpc<Cursor<::bytes::BytesMut>>>::Response, LibvirtError>
        where P: Pack<::bytes::Writer<::bytes::BytesMut>> + request::LibvirtRpc<Cursor<::bytes::BytesMut>>,
        <P as request::LibvirtRpc<Cursor<::bytes::BytesMut>>>::Response: 'static
    {
        self.request_sink_stream(procedure, payload, None, sink)
    }

    fn request_sink_stream<P>(&self, procedure: request::remote_procedure, payload: P, stream: Option<Sender<LibvirtResponse>>, sink: Option<Receiver<BytesMut>>) ->
     ::futures::BoxFuture<<P as request::LibvirtRpc<Cursor<::bytes::BytesMut>>>::Response, LibvirtError>
        where P: Pack<::bytes::Writer<::bytes::BytesMut>> + request::LibvirtRpc<Cursor<::bytes::BytesMut>>,
        <P as request::LibvirtRpc<Cursor<::bytes::BytesMut>>>::Response: 'static
     {
        let req = Self::pack(procedure, payload, stream, sink);
        match req {
            Err(e) => {
                future::err(e.into()).boxed()
            },
            Ok(req) => self.call(req)
                        .map_err(|e| e.into())
                        .and_then(Self::handle_response)
                        .boxed()
        }
    }

    /// Retrieves authentication methods (currently only unauthenticated connections are supported)
    pub fn auth(&self) -> ::futures::BoxFuture<request::AuthListResponse, LibvirtError> {
        let pl = request::AuthListRequest::new();
        self.request(request::remote_procedure::REMOTE_PROC_AUTH_LIST, pl)
    }

    /// Opens up a read-write connection to the system qemu hypervisor driver
    pub fn open(&self) -> ::futures::BoxFuture<(), LibvirtError> {
        let pl = request::ConnectOpenRequest::new();
        self.request(request::remote_procedure::REMOTE_PROC_CONNECT_OPEN, pl).map(|_| ()).boxed()
    }

    /// Can be used to obtain the version of the libvirt software in use on the host
    pub fn version(&self) -> ::futures::BoxFuture<(u32, u32, u32), LibvirtError> {
        let pl = request::GetLibVersionRequest::new();
        self.request(request::remote_procedure::REMOTE_PROC_CONNECT_GET_LIB_VERSION, pl).map(|resp| resp.version()).boxed()
    }

    pub fn domain(&self) -> DomainOperations {
        DomainOperations{client: self}
    }

    pub fn pool(&self) -> PoolOperations {
        PoolOperations{client: self}
    }

    pub fn volume(&self) -> VolumeOperations {
        VolumeOperations{client: self}
    }
}

/// Operations on libvirt storage volumes
pub struct VolumeOperations<'a> {
    client: &'a Client,
}

impl<'a> VolumeOperations<'a> {
    /// Create a storage volume within a pool based on an XML description. Not all pools support creation of volumes.
    pub fn create(&self, pool: &request::StoragePool, xml: &str,
                  flags: request::StorageVolCreateXmlFlags::StorageVolCreateXmlFlags) -> ::futures::BoxFuture<request::Volume, LibvirtError> {
        let payload = request::StorageVolCreateXmlRequest::new(pool, xml, flags);
        self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_VOL_CREATE_XML, payload).map(|resp| resp.into()).boxed()
    }

    /// Create a storage volume in the parent pool, using the 'clonevol' volume as input.
    /// Information for the new volume (name, perms) are passed via a typical volume XML description.
    pub fn create_from(&self, pool: &request::StoragePool, xml: &str, vol: &request::Volume,
                        flags: request::StorageVolCreateXmlFlags::StorageVolCreateXmlFlags) -> ::futures::BoxFuture<request::Volume, LibvirtError> {
        let payload = request::StorageVolCreateXmlFromRequest::new(pool, xml, vol, flags);
        self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_VOL_CREATE_XML_FROM, payload).map(|resp| resp.into()).boxed()
    }

    /// Delete the storage volume from the pool
    pub fn delete(&self, vol: request::Volume) -> ::futures::BoxFuture<(), LibvirtError> {
        let payload = request::StorageVolDeleteRequest::new(vol, 0);
        self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_VOL_DELETE, payload).map(|resp| resp.into()).boxed()
    }

    /// Ensure data previously on a volume is not accessible to future reads.
    /// The data to be wiped may include the format and possibly size information, so non-raw images might become raw with a different size.
    /// It is storage backend dependent whether the format and size information is regenerated once the initial volume wipe is completed.
    /// Depending on the actual volume representation, this call may not overwrite the physical location of the volume.
    /// For instance, files stored journaled, log structured, copy-on-write, versioned, and network file systems are known to be problematic.
    pub fn wipe(&self, vol: &request::Volume) -> ::futures::BoxFuture<(), LibvirtError> {
        let payload = request::StorageVolWipeRequest::new(vol, 0);
        self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_VOL_WIPE, payload).map(|resp| resp.into()).boxed()
    }

    pub fn lookup_by_name(&self, pool: &request::StoragePool, name: &str) -> ::futures::BoxFuture<request::Volume, LibvirtError> {
        let payload = request::StorageVolLookupByNameRequest::new(pool, name);
        self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_VOL_LOOKUP_BY_NAME, payload).map(|resp| resp.into()).boxed()
    }

    /// Changes the capacity of the storage volume @vol to @capacity.
    /// The operation will fail if the new capacity requires allocation that would exceed the remaining free space in the parent pool.
    /// The contents of the new capacity will appear as all zero bytes. The capacity value will be rounded to the granularity supported by the hypervisor.
    ///
    /// Normally, the operation will attempt to affect capacity with a minimum impact on allocation (that is, the default operation favors a sparse resize).
    /// If @flags contains VIR_STORAGE_VOL_RESIZE_ALLOCATE, then the operation will ensure that allocation is sufficient for the new capacity;
    /// this may make the operation take noticeably longer.

    /// Normally, the operation treats @capacity as the new size in bytes; but if @flags contains VIR_STORAGE_VOL_RESIZE_DELTA,
    /// then @capacity represents the size difference to add to the current size. It is up to the storage pool implementation whether unaligned
    /// requests are rounded up to the next valid boundary, or rejected.
    ///
    /// Normally, this operation should only be used to enlarge capacity; but if @flags contains VIR_STORAGE_VOL_RESIZE_SHRINK,
    /// it is possible to attempt a reduction in capacity even though it might cause data loss.
    /// If VIR_STORAGE_VOL_RESIZE_DELTA is also present, then @capacity is subtracted from the current size; without it,
    /// @capacity represents the absolute new size regardless of whether it is larger or smaller than the current size.
    pub fn resize(&self, vol: &request::Volume, capacity: u64, flags: request::StorageVolResizeFlags::StorageVolResizeFlags) -> ::futures::BoxFuture<(), LibvirtError> {
        let payload = request::StorageVolResizeRequest::new(vol, capacity, flags);
        self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_VOL_RESIZE, payload).map(|resp| resp.into()).boxed()
    }

    /// Download the content of the volume as a stream. If @length is zero, then the remaining contents of the volume after @offset will be downloaded.
    /// This call sets up an asynchronous stream; subsequent use of stream APIs is necessary to transfer the actual data,
    /// determine how much data is successfully transferred, and detect any errors.
    /// The results will be unpredictable if another active stream is writing to the storage volume.
    pub fn download(&self, vol: &request::Volume, offset: u64, length: u64) -> ::futures::BoxFuture<LibvirtStream, LibvirtError> {
        let pl = request::StorageVolDownloadRequest::new(vol, offset, length, 0);
        let (sender, receiver) = ::futures::sync::mpsc::channel(0);

        self.client.request_stream(request::remote_procedure::REMOTE_PROC_STORAGE_VOL_DOWNLOAD, pl, Some(sender)).map(move |_| {
            LibvirtStream::from(receiver)
        }).boxed()
    }

    /// Upload new content to the volume from a stream. This call will fail if @offset + @length exceeds the size of the volume.
    /// Otherwise, if @length is non-zero, an error will be raised if an attempt is made to upload greater than @length bytes of data.
    ///
    /// This call sets up an asynchronous stream; subsequent use of stream APIs is necessary to transfer the actual data, determine how much data
    /// is successfully transferred, and detect any errors. The results will be unpredictable if another active stream is writing to the storage volume.
    ///
    /// When the data stream is closed whether the upload is successful or not the target storage pool will be refreshed to reflect pool
    /// and volume changes as a result of the upload. Depending on the target volume storage backend and the source stream type for a successful upload, the target volume may take on the characteristics from the source stream such as format type, capacity, and allocation.
    pub fn upload(&self, vol: &request::Volume, offset: u64, length: u64) -> ::futures::BoxFuture<LibvirtSink, LibvirtError> {
        let pl = request::StorageVolUploadRequest::new(vol, offset, length, 0);
        let (sender, receiver) = ::futures::sync::mpsc::channel(64);
 
        self.client.request_sink(request::remote_procedure::REMOTE_PROC_STORAGE_VOL_UPLOAD, pl, Some(receiver)).map(move |_| {
           LibvirtSink { inner: sender }
        }).boxed()
    }

    pub fn upload_with<F, R>(&self, vol: &request::Volume, offset: u64, length: u64, uploader: F) -> ::futures::BoxFuture<(), LibvirtError>
    where F: FnOnce(LibvirtSink) -> R + Send + 'static,
          R: ::futures::IntoFuture + 'static,
          R::Future: Send + 'static,
          R::Item: Send + 'static,
          R::Error: Send + 'static,
     {
        use futures::{Future, Stream};
        let pl = request::StorageVolUploadRequest::new(vol, offset, length, 0);
        let (sink_sender, sink_receiver) = ::futures::sync::mpsc::channel(64);
        let (stream_sender, stream_receiver) = ::futures::sync::mpsc::channel(64);
 
        self.client.request_sink_stream(request::remote_procedure::REMOTE_PROC_STORAGE_VOL_UPLOAD, pl, Some(stream_sender), Some(sink_receiver))
                   .map(move |_| LibvirtSink { inner: sink_sender } )
                   .map(move |sink| uploader(sink))
                   .and_then(|_| stream_receiver.into_future().map_err(|e| panic!("Unexpected error in mpsc receiver: {:?}", e)))
                   .and_then(|(ev, _)| {
                        Client::handle_response(ev.unwrap())
                   }).boxed()
    }
}

/// Operations on libvirt storage pools
pub struct PoolOperations<'a> {
    client: &'a Client,
}

impl<'a> PoolOperations<'a> {
    /// Collect the list of storage pools
    pub fn list(&self, flags: request::ListAllStoragePoolsFlags::ListAllStoragePoolsFlags) -> ::futures::BoxFuture<Vec<request::StoragePool>, LibvirtError> {
        let payload = request::ListAllStoragePoolsRequest::new(flags);
        self.client.request(request::remote_procedure::REMOTE_PROC_CONNECT_LIST_ALL_STORAGE_POOLS, payload).map(|resp| resp.into()).boxed()
    }

    /// Define an inactive persistent storage pool or modify an existing persistent one from the XML description.
    pub fn define(&self, xml: &str) -> ::futures::BoxFuture<request::StoragePool, LibvirtError> {
        let payload = request::StoragePoolDefineXmlRequest::new(xml, 0);
        self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_POOL_DEFINE_XML, payload).map(|resp| resp.into()).boxed()
    }

    /// Fetch a storage pool based on its globally unique id
    pub fn lookup_by_uuid(&self, uuid: &::uuid::Uuid) -> ::futures::BoxFuture<request::StoragePool, LibvirtError> {
        let payload = request::StoragePoolLookupByUuidRequest::new(uuid);
        self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_POOL_LOOKUP_BY_UUID, payload).map(|resp| resp.into()).boxed()
    }

    /// Fetch a storage pool based on its name
    pub fn lookup_by_name(&self, name: &str) -> ::futures::BoxFuture<request::StoragePool, LibvirtError> {
        let payload = request::StoragePoolLookupByNameRequest::new(name);
        self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_POOL_LOOKUP_BY_NAME, payload).map(|resp| resp.into()).boxed()
    }

    /// Starts an inactive storage pool
    pub fn start(&self, pool: &request::StoragePool) -> ::futures::BoxFuture<(), LibvirtError> {
        let payload = request::StoragePoolCreateRequest::new(pool, 0);
        self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_POOL_CREATE, payload).map(|resp| resp.into()).boxed()
    }

    /// Destroy an active storage pool. This will deactivate the pool on the host, but keep any persistent config associated with it.
    /// If it has a persistent config it can later be restarted with start()
    pub fn destroy(&self, pool: &request::StoragePool) -> ::futures::BoxFuture<(), LibvirtError> {
        let payload = request::StoragePoolDestroyRequest::new(pool);
        self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_POOL_DESTROY, payload).map(|resp| resp.into()).boxed()
    }

    /// Undefine an inactive storage pool
    pub fn undefine(&self, pool: request::StoragePool) -> ::futures::BoxFuture<(), LibvirtError> {
        let payload = request::StoragePoolUndefineRequest::new(pool);
        self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_POOL_UNDEFINE, payload).map(|resp| resp.into()).boxed()
    }

    /// Fetch list of storage volume names
    pub fn list_volume_names(&self, pool: &request::StoragePool) -> ::futures::BoxFuture<Vec<String>, LibvirtError> {
        let payload = request::StoragePoolListVolumesRequest::new(pool, request::generated::REMOTE_STORAGE_VOL_LIST_MAX as i32);
        self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_POOL_LIST_VOLUMES, payload).map(|resp| resp.into()).boxed()
    }

    /// Collect the list of storage volumes
    pub fn list_volumes(&self, pool: &request::StoragePool) -> ::futures::BoxFuture<Vec<request::Volume>, LibvirtError> {
            let payload = request::StoragePoolListAllVolumesRequest::new(pool, 1, 0);
            self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_POOL_LIST_ALL_VOLUMES, payload).map(|resp| resp.into()).boxed()
    }
}

/// Operations on libvirt domains
pub struct DomainOperations<'a> {
    client: &'a Client,
}

impl<'a> DomainOperations<'a> {
    /// Collect a possibly-filtered list of all domains, and return an allocated array of information for each. 
    pub fn list(&self, flags: request::ListAllDomainFlags::ListAllDomainsFlags) -> ::futures::BoxFuture<Vec<request::Domain>, LibvirtError> {
        let payload = request::ListAllDomainsRequest::new(flags);
        self.client.request(request::remote_procedure::REMOTE_PROC_CONNECT_LIST_ALL_DOMAINS, payload).map(|resp| resp.into()).boxed()
    }

    /// Lookup a domain on the given hypervisor based on its UUID.
    pub fn lookup_by_uuid(&self, uuid: &::uuid::Uuid) -> ::futures::BoxFuture<request::Domain, LibvirtError> {
        let pl = request::DomainLookupByUuidRequest::new(uuid);
        self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_LOOKUP_BY_UUID, pl).map(|resp| resp.domain()).boxed()
    }

    pub fn register_event(&self, dom: &request::Domain, event: i32) -> ::futures::BoxFuture<EventStream<::request::DomainEvent>, LibvirtError> {
        let pl = request::DomainEventCallbackRegisterAnyRequest::new(event, dom);
        let map = self.client.events.clone();
        self.client.request(request::remote_procedure::REMOTE_PROC_CONNECT_DOMAIN_EVENT_CALLBACK_REGISTER_ANY, pl)
            .map(move |resp| {
                let id = resp.callback_id();
                debug!("REGISTERED CALLBACK ID {}", id);
                {
                    let mut map = map.lock().unwrap();
                    let (sender, receiver) = ::futures::sync::mpsc::channel(1024);
                    map.insert(id, sender);
                    EventStream{inner: receiver}
                }
            }).boxed()
    }
    /* TODO implement unregister */

    /// Launch a defined domain. If the call succeeds the domain moves from the defined to the running domains pools.
    pub fn start(&self, dom: request::Domain, flags: request::DomainCreateFlags::DomainCreateFlags) -> ::futures::BoxFuture<request::Domain, LibvirtError> {
        let pl = request::DomainCreateRequest::new(dom, flags);
        self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_CREATE_WITH_FLAGS, pl).map(|resp| resp.into()).boxed()
    }

    /// Destroy the domain object. The running instance is shutdown if not down already and all resources used by it are given back to the hypervisor.
    pub fn destroy(&self, dom: request::Domain, flags: request::DomainDestroyFlags::DomainDestroyFlags) -> ::futures::BoxFuture<(), LibvirtError> {
        let pl = request::DomainDestroyRequest::new(dom, flags);
        self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_DESTROY_FLAGS, pl).map(|_| ()).boxed()
    }

    /// Defines a domain, but does not start it. This definition is persistent, until explicitly undefined with virDomainUndefine().
    /// A previous definition for this domain would be overridden if it already exists.
    pub fn define(&self, xml: &str) -> ::futures::BoxFuture<request::Domain, LibvirtError> {
        let pl = request::DomainDefineXMLRequest::new(xml, 1); /* TODO: flags */
        self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_DEFINE_XML_FLAGS, pl).map(|resp| resp.into()).boxed()
    }

    /// Undefine a domain. If the domain is running, it's converted to transient domain, without stopping it.
    /// If the domain is inactive, the domain configuration is removed.
    pub fn undefine(&self, dom: request::Domain) -> ::futures::BoxFuture<(), LibvirtError> {
        let pl = request::DomainUndefineRequest::new(dom, 0); /* TODO: flags */
        self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_UNDEFINE_FLAGS, pl).map(|resp| resp.into()).boxed()
    }

    /// Shutdown a domain, the domain object is still usable thereafter, but the domain OS is being stopped.
    /// Note that the guest OS may ignore the request.
    ///
    /// Additionally, the hypervisor may check and support the domain 'on_poweroff' XML setting resulting in
    /// a domain that reboots instead of shutting down. For guests that react to a shutdown request,
    /// the differences from virDomainDestroy() are that the guests disk storage will be in a stable state
    /// rather than having the (virtual) power cord pulled, and this command returns as soon as the shutdown
    /// request is issued rather than blocking until the guest is no longer running.
    pub fn shutdown(&self, dom: &request::Domain) -> ::futures::BoxFuture<(), LibvirtError> {
        let pl = request::DomainShutdownRequest::new(dom);
        self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_SHUTDOWN, pl).map(|resp| resp.into()).boxed()
    }

    /// Reboot a domain, the domain object is still usable thereafter, but the domain OS is being stopped for a restart.
    /// Note that the guest OS may ignore the request.
    ///
    /// Additionally, the hypervisor may check and support the domain 'on_reboot' XML setting resulting in a domain that shuts down instead of rebooting.
    pub fn reboot(&self, dom: &request::Domain) -> ::futures::BoxFuture<(), LibvirtError> {
        let pl = request::DomainRebootRequest::new(dom, 0);
        self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_REBOOT, pl).map(|resp| resp.into()).boxed()
    }

    /// Reset a domain immediately without any guest OS shutdown.
    /// Reset emulates the power reset button on a machine, where all hardware sees the RST line set and reinitializes internal state.
    ///
    /// Note that there is a risk of data loss caused by reset without any guest OS shutdown.
    pub fn reset(&self, dom: &request::Domain) -> ::futures::BoxFuture<(), LibvirtError> {
        let pl = request::DomainResetRequest::new(dom, 0);
        self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_RESET, pl).map(|resp| resp.into()).boxed()
    }

    /// Take a screenshot of current domain console as a stream. The image format is hypervisor specific.
    /// Moreover, some hypervisors supports multiple displays per domain. These can be distinguished by @screen argument.
    ///
    /// This call sets up a stream; subsequent use of stream API is necessary to transfer actual data, determine how much
    /// data is successfully transferred, and detect any errors.
    ///
    /// The screen ID is the sequential number of screen. In case of multiple graphics cards, heads are enumerated before devices,
    /// e.g. having two graphics cards, both with four heads, screen ID 5 addresses the second head on the second card.
    pub fn screenshot(&self, dom: &request::Domain, screen: u32) -> ::futures::BoxFuture<(Option<String>, LibvirtStream), LibvirtError> {
        let pl = request::DomainScreenshotRequest::new(dom, screen, 0);
        let (sender, receiver) = ::futures::sync::mpsc::channel(0);

        self.client.request_stream(request::remote_procedure::REMOTE_PROC_DOMAIN_SCREENSHOT, pl, Some(sender)).map(move |resp|{
            (resp.into(), LibvirtStream::from(receiver))
        }).boxed()
    }
}

impl Service for Client {
    type Request = LibvirtRequest;
    type Response = LibvirtResponse;
    type Error = ::std::io::Error;
    type Future = ::futures::BoxFuture<Self::Response, Self::Error>;

    fn call(&self, req: Self::Request) -> Self::Future {
        let inner = self.inner.lock().unwrap();
        inner.call(req).boxed()
    }
}

#[test]
fn pools_and_volumes() {
    use ::tokio_core::reactor::Core;
    use ::futures::{Stream,Sink};

    ::env_logger::init();
    let mut core = Core::new().unwrap();
    let handle = core.handle(); 
    //let cpupool = ::futures_cpupool::new(4);
    let client = Client::connect("/var/run/libvirt/libvirt-sock", &handle).unwrap();
    let result = core.run({
        client.auth()
            .and_then(|_| client.open())
            .and_then(|_| client.version())
            .and_then(|_| client.pool().list(request::ListAllStoragePoolsFlags::ListAllStoragePoolsFlags::empty()))
            .and_then(|vols| client.volume().lookup_by_name(&vols[0], "test-volume"))
            .and_then(|vol| {
                use std::fs;
                use std::os::unix::fs::MetadataExt;
                let m = fs::metadata("/etc/passwd").unwrap();
                let len = m.size(); 
                println!("Uploading file of size {}", len);
                client.volume().upload(&vol, 0, len)
            })
            .and_then(|sink| {
                handle.spawn({
                    println!("Got upload stream");
                    read_file_to_sink("/etc/passwd", sink).and_then(|_| {
                        println!("UPLOADED");
                        Ok(())
                    }).or_else(|e| {
                        println!("UPLOAD FAIL {:?}", e);
                        Ok(())
                    })

                    /*
                    use std::io::Read;
                    use std::fs::File;
                    let mut file = File::open("/etc/passwd").unwrap();
                    let mut buf = BytesMut::with_capacity(1024 * 1024);
                    unsafe { buf.set_len(1024) };
                    file.read_exact(&mut buf[0..1024]).unwrap();
                    sink.send(buf).and_then(|_| {
                        println!("UPLOADED");
                        Ok(())
                    }).or_else(|e| {
                        println!("UPLOAD FAIL {:?}", e);
                        Ok(())
                    })
                    */
                });
                Ok(())
            })
    }).unwrap();

    println!("RESULT: {:?}", result);

    loop {
        core.turn(None);
    }
}

/*
#[test]
fn pools_and_volumes() {
    use ::tokio_core::reactor::Core;
    use ::futures::Stream;

    ::env_logger::init();
    let mut core = Core::new().unwrap();
    let handle = core.handle(); 
    let client = Client::connect("/var/run/libvirt/libvirt-sock", &handle).unwrap();
    let result = core.run({
        client.auth()
            .and_then(|_| client.open())
            .and_then(|_| client.version())
            .and_then(|_| client.pool().list(request::ListAllStoragePoolsFlags::ListAllStoragePoolsFlags::empty()))
            .and_then(|vols| client.volume().lookup_by_name(&vols[0], "test-volume"))
            .and_then(|vol| client.volume().download(&vol, 0, 1024))
            .and_then(|stream| {
                println!("Got download stream");
                handle.spawn({
                    let buf = BytesMut::with_capacity(1024 * 1024);
                    stream.fold(buf, move |mut buf, part| {
                        buf.extend_from_slice(&part);
                        future::ok(buf)
                    }).and_then(|buf| {
                        use std::io::Write;
                        use std::fs::OpenOptions;
                        println!("FINAL RESULT {:?}", buf.len());
                        let mut f = OpenOptions::new().write(true).create(true).open("test.img").unwrap();
                        f.write_all(&buf);
                        Ok(())
                    })
                });
                Ok(())
            })
    }).unwrap();

    println!("RESULT: {:?}", result);

    loop {
        core.turn(None);
    }
}
*/

/*
#[test]
fn such_async() {
    use ::tokio_core::reactor::Core;
    use ::futures::Stream;

    ::env_logger::init();
    let mut core = Core::new().unwrap();
    let handle = core.handle(); 
    let client = Client::connect("/var/run/libvirt/libvirt-sock", &handle).unwrap();
    let uuid = ::uuid::Uuid::parse_str("61737ee1-8fd0-47de-a7af-156102602cf1").unwrap();
    let result = core.run({
        client.auth()
            .and_then(|_| client.open())
            .and_then(|_| client.version())
            .and_then(|_| client.domain().list(request::ListAllDomainFlags::DOMAINS_ACTIVE | request::ListAllDomainFlags::DOMAINS_INACTIVE))
            .and_then(|_| client.pool().list(request::ListAllStoragePoolsFlags::ListAllStoragePoolsFlags::empty()).map(|list| println!("{:?}",list)))
            .and_then(|_| client.domain().lookup_by_uuid(&uuid))
            .and_then(|dom| {
                client.domain().start(dom, request::DomainCreateFlags::DomainCreateFlags::empty())
            }).and_then(|dom| {
                client.domain().screenshot(&dom, 0)
            }).and_then(|(mime, stream)| {
                println!("Got {:?} stream", mime);
                handle.spawn({
                    let buf = BytesMut::with_capacity(1024 * 1024);
                    stream.fold(buf, move |mut buf, part| {
                        buf.extend_from_slice(&part);
                        future::ok(buf)
                    }).and_then(|buf| {
                        use std::io::Write;
                        use std::fs::OpenOptions;
                        println!("FINAL RESULT {:?}", buf.len());
                        let mut f = OpenOptions::new().write(true).create(true).open("test.ppm").unwrap();
                        f.write_all(&buf);
                        Ok(())
                    })
                });
                Ok(())
            })
             /*.and_then(|dom| {
                client.domain().register_event(&dom, 0)
            }).and_then(|events| {
                handle.spawn(events.for_each(|ev| {
                    println!("EVENT {:?}", ev);
                    Ok(())
                }));
                Ok(())
            })
            */
    }).unwrap();
    //println!("RESULT {:?}", result);
    loop {
        /*
        result.for_each(|ev| {
            println!("EVENT {:?}", ev);
            Ok(())
        })
        */
        core.turn(None);
        //println!("CORE TURNED");
    }
}
*/