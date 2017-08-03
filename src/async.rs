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

pub type LibvirtFuture<T> = Box<Future<Item = T, Error = LibvirtError>>;

/// Libvirt client
#[derive(Clone)]
pub struct Client {
    inner: multiplex::ClientService<::tokio_uds::UnixStream, LibvirtProto>,
}

impl Client {
    /// opens libvirt connection over unix socket
    pub fn connect<P: AsRef<Path>>(path: P, handle: &::tokio_core::reactor::Handle) -> Result<Client, ::std::io::Error> {
        use ::tokio_uds_proto::UnixClient;
        UnixClient::new(LibvirtProto)
                .connect(path, handle)
                .map(|inner| Client {
                     inner: inner,
                })
    }

    fn pack<P: Pack<::bytes::Writer<::bytes::BytesMut>>>(procedure: request::remote_procedure,
                      payload: P,
                      stream: Option<Sender<LibvirtResponse>>,
                      sink: Option<Receiver<BytesMut>>,
                      event: Option<request::remote_procedure>) -> Result<LibvirtRequest, ::xdr_codec::Error> {
        let buf = BytesMut::with_capacity(4096);
        let buf = {
            let mut writer = buf.writer();
            try!(payload.pack(&mut writer));
            writer.into_inner()
        };
        let req = LibvirtRequest {
            stream: stream,
            sink: sink,
            event: event,
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
     LibvirtFuture<<P as request::LibvirtRpc<Cursor<::bytes::BytesMut>>>::Response>
        where P: Pack<::bytes::Writer<::bytes::BytesMut>> + request::LibvirtRpc<Cursor<::bytes::BytesMut>>,
        <P as request::LibvirtRpc<Cursor<::bytes::BytesMut>>>::Response: 'static
    {
        self.request_stream(procedure, payload, None, None)
    }

    fn request_stream<P>(&self, procedure: request::remote_procedure, payload: P, stream: Option<Sender<LibvirtResponse>>, event: Option<request::remote_procedure>) ->
     Box<Future<Item = <P as request::LibvirtRpc<Cursor<::bytes::BytesMut>>>::Response, Error = LibvirtError>>
        where P: Pack<::bytes::Writer<::bytes::BytesMut>> + request::LibvirtRpc<Cursor<::bytes::BytesMut>>,
        <P as request::LibvirtRpc<Cursor<::bytes::BytesMut>>>::Response: 'static
    {
        self.request_sink_stream(procedure, payload, stream, None, event)
    }

    fn request_sink<P>(&self, procedure: request::remote_procedure, payload: P, sink: Option<Receiver<BytesMut>>) ->
     Box<Future<Item = <P as request::LibvirtRpc<Cursor<::bytes::BytesMut>>>::Response, Error = LibvirtError>>
        where P: Pack<::bytes::Writer<::bytes::BytesMut>> + request::LibvirtRpc<Cursor<::bytes::BytesMut>>,
        <P as request::LibvirtRpc<Cursor<::bytes::BytesMut>>>::Response: 'static
    {
        self.request_sink_stream(procedure, payload, None, sink, None)
    }

    fn request_sink_stream<P>(&self, procedure: request::remote_procedure,
                                     payload: P,
                                     stream: Option<Sender<LibvirtResponse>>,
                                     sink: Option<Receiver<BytesMut>>,
                                     event: Option<request::remote_procedure>) ->
     Box<Future<Item = <P as request::LibvirtRpc<Cursor<::bytes::BytesMut>>>::Response, Error = LibvirtError>>
        where P: Pack<::bytes::Writer<::bytes::BytesMut>> + request::LibvirtRpc<Cursor<::bytes::BytesMut>>,
        <P as request::LibvirtRpc<Cursor<::bytes::BytesMut>>>::Response: 'static
     {
        let req = Self::pack(procedure, payload, stream, sink, event);
        match req {
            Err(e) => {
                Box::new(future::err(e.into()))
            },
            Ok(req) => Box::new(self.call(req)
                        .map_err(|e| e.into())
                        .and_then(Self::handle_response))
        }
    }

    /// Retrieves authentication methods (currently only unauthenticated connections are supported)
    pub fn auth(&self) -> LibvirtFuture<request::AuthListResponse> {
        let pl = request::AuthListRequest::new();
        self.request(request::remote_procedure::REMOTE_PROC_AUTH_LIST, pl)
    }

    /// Opens up a read-write connection to the system qemu hypervisor driver
    pub fn open(&self) -> LibvirtFuture<()> {
        let pl = request::ConnectOpenRequest::new();
        Box::new(self.request(request::remote_procedure::REMOTE_PROC_CONNECT_OPEN, pl).map(|_| ()))
    }

    /// Can be used to obtain the version of the libvirt software in use on the host
    pub fn version(&self) -> LibvirtFuture<(u32, u32, u32)> {
        let pl = request::GetLibVersionRequest::new();
        Box::new(self.request(request::remote_procedure::REMOTE_PROC_CONNECT_GET_LIB_VERSION, pl).map(|resp| resp.version()))
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
                  flags: request::StorageVolCreateXmlFlags::StorageVolCreateXmlFlags) -> LibvirtFuture<request::Volume> {
        let payload = request::StorageVolCreateXmlRequest::new(pool, xml, flags);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_VOL_CREATE_XML, payload).map(|resp| resp.into()))
    }

    /// Create a storage volume in the parent pool, using the 'clonevol' volume as input.
    /// Information for the new volume (name, perms) are passed via a typical volume XML description.
    pub fn create_from(&self, pool: &request::StoragePool, xml: &str, vol: &request::Volume,
                        flags: request::StorageVolCreateXmlFlags::StorageVolCreateXmlFlags) -> LibvirtFuture<request::Volume> {
        let payload = request::StorageVolCreateXmlFromRequest::new(pool, xml, vol, flags);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_VOL_CREATE_XML_FROM, payload).map(|resp| resp.into()))
    }

    /// Delete the storage volume from the pool
    pub fn delete(&self, vol: request::Volume) -> LibvirtFuture<()> {
        let payload = request::StorageVolDeleteRequest::new(vol, 0);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_VOL_DELETE, payload).map(|resp| resp.into()))
    }

    /// Ensure data previously on a volume is not accessible to future reads.
    /// The data to be wiped may include the format and possibly size information, so non-raw images might become raw with a different size.
    /// It is storage backend dependent whether the format and size information is regenerated once the initial volume wipe is completed.
    /// Depending on the actual volume representation, this call may not overwrite the physical location of the volume.
    /// For instance, files stored journaled, log structured, copy-on-write, versioned, and network file systems are known to be problematic.
    pub fn wipe(&self, vol: &request::Volume) -> LibvirtFuture<()> {
        let payload = request::StorageVolWipeRequest::new(vol, 0);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_VOL_WIPE, payload).map(|resp| resp.into()))
    }

    pub fn lookup_by_name(&self, pool: &request::StoragePool, name: &str) -> LibvirtFuture<request::Volume> {
        let payload = request::StorageVolLookupByNameRequest::new(pool, name);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_VOL_LOOKUP_BY_NAME, payload).map(|resp| resp.into()))
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
    pub fn resize(&self, vol: &request::Volume, capacity: u64, flags: request::StorageVolResizeFlags::StorageVolResizeFlags) -> LibvirtFuture<()> {
        let payload = request::StorageVolResizeRequest::new(vol, capacity, flags);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_VOL_RESIZE, payload).map(|resp| resp.into()))
    }

    /// Download the content of the volume as a stream. If @length is zero, then the remaining contents of the volume after @offset will be downloaded.
    /// This call sets up an asynchronous stream; subsequent use of stream APIs is necessary to transfer the actual data,
    /// determine how much data is successfully transferred, and detect any errors.
    /// The results will be unpredictable if another active stream is writing to the storage volume.
    pub fn download(&self, vol: &request::Volume, offset: u64, length: u64) -> LibvirtFuture<LibvirtStream> {
        let pl = request::StorageVolDownloadRequest::new(vol, offset, length, 0);
        let (sender, receiver) = ::futures::sync::mpsc::channel(0);

        Box::new(self.client.request_stream(request::remote_procedure::REMOTE_PROC_STORAGE_VOL_DOWNLOAD, pl, Some(sender), None).map(move |_| {
            LibvirtStream::from(receiver)
        }))
    }

    /// Upload new content to the volume from a stream. This call will fail if @offset + @length exceeds the size of the volume.
    /// Otherwise, if @length is non-zero, an error will be raised if an attempt is made to upload greater than @length bytes of data.
    ///
    /// This call sets up an asynchronous stream; subsequent use of stream APIs is necessary to transfer the actual data, determine how much data
    /// is successfully transferred, and detect any errors. The results will be unpredictable if another active stream is writing to the storage volume.
    ///
    /// When the data stream is closed whether the upload is successful or not the target storage pool will be refreshed to reflect pool
    /// and volume changes as a result of the upload. Depending on the target volume storage backend and the source stream type for a successful upload, the target volume may take on the characteristics from the source stream such as format type, capacity, and allocation.
    pub fn upload(&self, vol: &request::Volume, offset: u64, length: u64) -> LibvirtFuture<LibvirtSink> {
        let pl = request::StorageVolUploadRequest::new(vol, offset, length, 0);
        let (sender, receiver) = ::futures::sync::mpsc::channel(64);
 
        Box::new(self.client.request_sink(request::remote_procedure::REMOTE_PROC_STORAGE_VOL_UPLOAD, pl, Some(receiver)).map(move |_| {
           LibvirtSink { inner: sender }
        }))
    }

    /// Same as `upload` but accepts callback and returns upload result
    pub fn upload_with<F, R>(&self, vol: &request::Volume, offset: u64, length: u64, uploader: F) -> Box<Future<Item = (), Error = R::Error>>
    where F: FnOnce(LibvirtSink) -> R + Send + 'static,
          R: ::futures::IntoFuture + 'static,
          R::Future: Send + 'static,
          R::Item: Send + 'static,
          R::Error: Send + 'static + From<LibvirtError>,
     {
        use futures::{Future, Stream};
        let pl = request::StorageVolUploadRequest::new(vol, offset, length, 0);
        let (sink_sender, sink_receiver) = ::futures::sync::mpsc::channel(64);
        let (stream_sender, stream_receiver) = ::futures::sync::mpsc::channel(64);
 
        Box::new(self.client.request_sink_stream(request::remote_procedure::REMOTE_PROC_STORAGE_VOL_UPLOAD, pl, Some(stream_sender), Some(sink_receiver), None)
                   .map_err(|e| e.into())
                   .and_then(move |_| uploader(LibvirtSink { inner: sink_sender }).into_future())
                   .and_then(|_| stream_receiver.into_future().map_err(|e| panic!("Unexpected error in mpsc receiver: {:?}", e)))
                   .and_then(|(ev, _)| {
                        Client::handle_response(ev.unwrap()).map_err(|e| e.into())
                   }))
    }
}

/// Operations on libvirt storage pools
pub struct PoolOperations<'a> {
    client: &'a Client,
}

impl<'a> PoolOperations<'a> {
    /// Collect the list of storage pools
    pub fn list(&self, flags: request::ListAllStoragePoolsFlags::ListAllStoragePoolsFlags) -> LibvirtFuture<Vec<request::StoragePool>> {
        let payload = request::ListAllStoragePoolsRequest::new(flags);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_CONNECT_LIST_ALL_STORAGE_POOLS, payload).map(|resp| resp.into()))
    }

    /// Define an inactive persistent storage pool or modify an existing persistent one from the XML description.
    pub fn define(&self, xml: &str) -> LibvirtFuture<request::StoragePool> {
        let payload = request::StoragePoolDefineXmlRequest::new(xml, 0);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_POOL_DEFINE_XML, payload).map(|resp| resp.into()))
    }

    /// Fetch a storage pool based on its globally unique id
    pub fn lookup_by_uuid(&self, uuid: &::uuid::Uuid) -> LibvirtFuture<request::StoragePool> {
        let payload = request::StoragePoolLookupByUuidRequest::new(uuid);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_POOL_LOOKUP_BY_UUID, payload).map(|resp| resp.into()))
    }

    /// Fetch a storage pool based on its name
    pub fn lookup_by_name(&self, name: &str) -> LibvirtFuture<request::StoragePool> {
        let payload = request::StoragePoolLookupByNameRequest::new(name);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_POOL_LOOKUP_BY_NAME, payload).map(|resp| resp.into()))
    }

    /// Starts an inactive storage pool
    pub fn start(&self, pool: &request::StoragePool) -> LibvirtFuture<()> {
        let payload = request::StoragePoolCreateRequest::new(pool, 0);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_POOL_CREATE, payload).map(|resp| resp.into()))
    }

    /// Destroy an active storage pool. This will deactivate the pool on the host, but keep any persistent config associated with it.
    /// If it has a persistent config it can later be restarted with start()
    pub fn destroy(&self, pool: &request::StoragePool) -> LibvirtFuture<()> {
        let payload = request::StoragePoolDestroyRequest::new(pool);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_POOL_DESTROY, payload).map(|resp| resp.into()))
    }

    /// Undefine an inactive storage pool
    pub fn undefine(&self, pool: request::StoragePool) -> LibvirtFuture<()> {
        let payload = request::StoragePoolUndefineRequest::new(pool);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_POOL_UNDEFINE, payload).map(|resp| resp.into()))
    }

    /// Fetch list of storage volume names
    pub fn list_volume_names(&self, pool: &request::StoragePool) -> LibvirtFuture<Vec<String>> {
        let payload = request::StoragePoolListVolumesRequest::new(pool, request::generated::REMOTE_STORAGE_VOL_LIST_MAX as i32);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_POOL_LIST_VOLUMES, payload).map(|resp| resp.into()))
    }

    /// Collect the list of storage volumes
    pub fn list_volumes(&self, pool: &request::StoragePool) -> LibvirtFuture<Vec<request::Volume>> {
        let payload = request::StoragePoolListAllVolumesRequest::new(pool, 1, 0);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_STORAGE_POOL_LIST_ALL_VOLUMES, payload).map(|resp| resp.into()))
    }
}

/// Operations on libvirt domains
pub struct DomainOperations<'a> {
    client: &'a Client,
}

impl<'a> DomainOperations<'a> {
    pub fn info(&self, dom: &request::Domain) -> LibvirtFuture<request::DomainInfo> {
        let payload = request::DomainGetInfoRequest::new(dom);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_GET_INFO, payload).map(|resp| resp.into()))
    }

    /// Collect a possibly-filtered list of all domains, and return an allocated array of information for each. 
    pub fn list(&self, flags: request::ListAllDomainsFlags::ListAllDomainsFlags) -> LibvirtFuture<Vec<request::Domain>> {
        let payload = request::ListAllDomainsRequest::new(flags);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_CONNECT_LIST_ALL_DOMAINS, payload).map(|resp| resp.into()))
    }

    /// Lookup a domain on the given hypervisor based on its UUID.
    pub fn lookup_by_uuid(&self, uuid: &::uuid::Uuid) -> LibvirtFuture<request::Domain> {
        let pl = request::DomainLookupByUuidRequest::new(uuid);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_LOOKUP_BY_UUID, pl).map(|resp| resp.domain()))
    }

    fn register_event<T: request::DomainEvent>(&self, dom: Option<&request::Domain>, event: request::DomainEventId) -> LibvirtFuture<EventStream<T>> {
        let pl = request::DomainEventCallbackRegisterAnyRequest::new(event as i32, dom);
        let (sender, receiver) = ::futures::sync::mpsc::channel(1024);
        let event_procedure = event.get_method();
        Box::new(self.client.request_stream(request::remote_procedure::REMOTE_PROC_CONNECT_DOMAIN_EVENT_CALLBACK_REGISTER_ANY, pl, Some(sender), Some(event_procedure))
            .map(move |resp| {
                let id = resp.callback_id();
                debug!("REGISTERED CALLBACK ID {}", id);
                {
                    EventStream::new(receiver, Client::handle_response)
                }
            }))
    }

    pub fn register_lifecycle_event(&self, dom: Option<&request::Domain>) -> LibvirtFuture<EventStream<request::DomainLifecycleEvent>> {
        self.register_event(dom, request::DomainEventId::Lifecycle)
    }

    pub fn register_reboot_event(&self, dom: Option<&request::Domain>) -> LibvirtFuture<EventStream<request::DomainRebootEvent>> {
        self.register_event(dom, request::DomainEventId::Reboot)
    }
    /* TODO implement unregister */

    /// Launch a defined domain. If the call succeeds the domain moves from the defined to the running domains pools.
    pub fn start(&self, dom: request::Domain, flags: request::DomainCreateFlags::DomainCreateFlags) -> LibvirtFuture<request::Domain> {
        let pl = request::DomainCreateRequest::new(dom, flags);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_CREATE_WITH_FLAGS, pl).map(|resp| resp.into()))
    }

    /// Destroy the domain object. The running instance is shutdown if not down already and all resources used by it are given back to the hypervisor.
    pub fn destroy(&self, dom: &request::Domain, flags: request::DomainDestroyFlags::DomainDestroyFlags) -> LibvirtFuture<()> {
        let pl = request::DomainDestroyRequest::new(dom, flags);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_DESTROY_FLAGS, pl).map(|_| ()))
    }

    /// Defines a domain, but does not start it. This definition is persistent, until explicitly undefined with virDomainUndefine().
    /// A previous definition for this domain would be overridden if it already exists.
    pub fn define(&self, xml: &str) -> LibvirtFuture<request::Domain> {
        let pl = request::DomainDefineXMLRequest::new(xml, 1); /* TODO: flags */
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_DEFINE_XML_FLAGS, pl).map(|resp| resp.into()))
    }

    /// Undefine a domain. If the domain is running, it's converted to transient domain, without stopping it.
    /// If the domain is inactive, the domain configuration is removed.
    pub fn undefine(&self, dom: request::Domain) -> LibvirtFuture<()> {
        let pl = request::DomainUndefineRequest::new(dom, 0); /* TODO: flags */
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_UNDEFINE_FLAGS, pl).map(|resp| resp.into()))
    }

    /// Shutdown a domain, the domain object is still usable thereafter, but the domain OS is being stopped.
    /// Note that the guest OS may ignore the request.
    ///
    /// Additionally, the hypervisor may check and support the domain 'on_poweroff' XML setting resulting in
    /// a domain that reboots instead of shutting down. For guests that react to a shutdown request,
    /// the differences from virDomainDestroy() are that the guests disk storage will be in a stable state
    /// rather than having the (virtual) power cord pulled, and this command returns as soon as the shutdown
    /// request is issued rather than blocking until the guest is no longer running.
    pub fn shutdown(&self, dom: &request::Domain) -> LibvirtFuture<()> {
        let pl = request::DomainShutdownRequest::new(dom);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_SHUTDOWN, pl).map(|resp| resp.into()))
    }

    /// Reboot a domain, the domain object is still usable thereafter, but the domain OS is being stopped for a restart.
    /// Note that the guest OS may ignore the request.
    ///
    /// Additionally, the hypervisor may check and support the domain 'on_reboot' XML setting resulting in a domain that shuts down instead of rebooting.
    pub fn reboot(&self, dom: &request::Domain) -> LibvirtFuture<()> {
        let pl = request::DomainRebootRequest::new(dom, 0);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_REBOOT, pl).map(|resp| resp.into()))
    }

    /// Reset a domain immediately without any guest OS shutdown.
    /// Reset emulates the power reset button on a machine, where all hardware sees the RST line set and reinitializes internal state.
    ///
    /// Note that there is a risk of data loss caused by reset without any guest OS shutdown.
    pub fn reset(&self, dom: &request::Domain) -> LibvirtFuture<()> {
        let pl = request::DomainResetRequest::new(dom, 0);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_RESET, pl).map(|resp| resp.into()))
    }

    /// Take a screenshot of current domain console as a stream. The image format is hypervisor specific.
    /// Moreover, some hypervisors supports multiple displays per domain. These can be distinguished by @screen argument.
    ///
    /// This call sets up a stream; subsequent use of stream API is necessary to transfer actual data, determine how much
    /// data is successfully transferred, and detect any errors.
    ///
    /// The screen ID is the sequential number of screen. In case of multiple graphics cards, heads are enumerated before devices,
    /// e.g. having two graphics cards, both with four heads, screen ID 5 addresses the second head on the second card.
    pub fn screenshot(&self, dom: &request::Domain, screen: u32) -> LibvirtFuture<(Option<String>, LibvirtStream)> {
        let pl = request::DomainScreenshotRequest::new(dom, screen, 0);
        let (sender, receiver) = ::futures::sync::mpsc::channel(0);

        Box::new(self.client.request_stream(request::remote_procedure::REMOTE_PROC_DOMAIN_SCREENSHOT, pl, Some(sender), None).map(move |resp|{
            (resp.into(), LibvirtStream::from(receiver))
        }))
    }


    /// Attach a virtual device to a domain, using the flags parameter to control how the device is attached.
    /// VIR_DOMAIN_AFFECT_CURRENT specifies that the device allocation is made based on current domain state.
    /// VIR_DOMAIN_AFFECT_LIVE specifies that the device shall be allocated to the active domain instance only and is not added
    /// to the persisted domain configuration.
    ///
    /// VIR_DOMAIN_AFFECT_CONFIG specifies that the device shall be allocated to the persisted domain configuration only.
    /// Note that the target hypervisor must return an error if unable to satisfy flags.
    /// E.g. the hypervisor driver will return failure if LIVE is specified but it only supports modifying the persisted device allocation.
    /// For compatibility, this method can also be used to change the media in an existing CDROM/Floppy device, however,
    /// applications are recommended to use the virDomainUpdateDeviceFlag method instead.
    ///
    /// Be aware that hotplug changes might not persist across a domain going into S4 state (also known as hibernation)
    /// unless you also modify the persistent domain definition.
    pub fn attach_device(&self, dom: &request::Domain, xml: &str, flags: request::DomainModificationImpact::DomainModificationImpact) -> LibvirtFuture<()> {
        let pl = request::DomainAttachDeviceRequest::new(dom, xml, flags);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_ATTACH_DEVICE_FLAGS, pl).map(|resp| resp.into()))
    }

    /// Detach a virtual device from a domain, using the flags parameter to control how the device is detached.
    /// VIR_DOMAIN_AFFECT_CURRENT specifies that the device allocation is removed based on current domain state.
    /// VIR_DOMAIN_AFFECT_LIVE specifies that the device shall be deallocated from the active domain instance only
    /// and is not from the persisted domain configuration.
    /// VIR_DOMAIN_AFFECT_CONFIG specifies that the device shall be deallocated from the persisted domain configuration only.
    /// Note that the target hypervisor must return an error if unable to satisfy flags.
    /// E.g. the hypervisor driver will return failure if LIVE is specified but it only supports removing the persisted device allocation.
    /// Some hypervisors may prevent this operation if there is a current block copy operation on the device being detached;
    /// in that case, use virDomainBlockJobAbort() to stop the block copy first.
    /// Beware that depending on the hypervisor and device type, detaching a device from a running domain may be asynchronous.
    /// That is, calling virDomainDetachDeviceFlags may just request device removal while the device is actually removed later
    /// (in cooperation with a guest OS). Previously, this fact was ignored and the device could have been removed from domain
    /// configuration before it was actually removed by the hypervisor causing various failures on subsequent operations.
    /// To check whether the device was successfully removed, either recheck domain configuration using virDomainGetXMLDesc()
    /// or add a handler for the VIR_DOMAIN_EVENT_ID_DEVICE_REMOVED event. In case the device is already gone when virDomainDetachDeviceFlags
    /// returns, the event is delivered before this API call ends. To help existing clients work better in most cases,
    /// this API will try to transform an asynchronous device removal that finishes shortly after the request into a synchronous removal.
    /// In other words, this API may wait a bit for the removal to complete in case it was not synchronous.
    ///
    /// Be aware that hotplug changes might not persist across a domain going into S4 state (also known as hibernation) unless you
    /// also modify the persistent domain definition.
    ///
    /// The supplied XML description of the device should be as specific as its definition in the domain XML.
    /// The set of attributes used to match the device are internal to the drivers. Using a partial definition, or attempting to detach
    /// a device that is not present in the domain XML, but shares some specific attributes with one that is present, may lead to unexpected results.
    pub fn detach_device(&self, dom: &request::Domain, xml: &str, flags: request::DomainModificationImpact::DomainModificationImpact) -> LibvirtFuture<()> {
        let pl = request::DomainDetachDeviceRequest::new(dom, xml, flags);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_DETACH_DEVICE_FLAGS, pl).map(|resp| resp.into()))
    }

    /// Change a virtual device on a domain, using the flags parameter to control how the device is changed.
    /// VIR_DOMAIN_AFFECT_CURRENT specifies that the device change is made based on current domain state.
    /// VIR_DOMAIN_AFFECT_LIVE specifies that the device shall be changed on the active domain instance
    /// only and is not added to the persisted domain configuration.
    /// VIR_DOMAIN_AFFECT_CONFIG specifies that the device shall be changed on the persisted domain configuration only.
    /// Note that the target hypervisor must return an error if unable to satisfy flags.
    /// E.g. the hypervisor driver will return failure if LIVE is specified but it only supports modifying the persisted device allocation.
    /// This method is used for actions such changing CDROM/Floppy device media, altering the graphics configuration such as password,
    /// reconfiguring the NIC device backend connectivity, etc.
    pub fn update_device(&self, dom: &request::Domain, xml: &str, flags: request::DomainModificationImpact::DomainModificationImpact) -> LibvirtFuture<()> {
        let pl = request::DomainUpdateDeviceRequest::new(dom, xml, flags);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_UPDATE_DEVICE_FLAGS, pl).map(|resp| resp.into()))
    }

    /// Dynamically change the target amount of physical memory allocated to a domain.
    pub fn set_memory(&self, dom: &request::Domain, size: u64, flags: request::DomainModificationImpact::DomainModificationImpact) -> LibvirtFuture<()> {
        let pl = request::DomainSetMemoryRequest::new(dom, size, flags);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_SET_MEMORY_FLAGS, pl).map(|resp| resp.into()))
    }

    /// Provide an XML description of the domain. The description may be reused later to relaunch the domain with virDomainCreateXML().
    /// No security-sensitive data will be included unless @flags contains VIR_DOMAIN_XML_SECURE;
    /// this flag is rejected on read-only connections. If @flags includes VIR_DOMAIN_XML_INACTIVE,
    /// then the XML represents the configuration that will be used on the next boot of a persistent domain;
    /// otherwise, the configuration represents the currently running domain.
    /// If @flags contains VIR_DOMAIN_XML_UPDATE_CPU, then the portion of the domain XML describing CPU capabilities
    /// is modified to match actual capabilities of the host.
    pub fn get_xml(&self, dom: &request::Domain, flags: request::DomainXmlFlags::DomainXmlFlags) -> LibvirtFuture<String> {
        let pl = request::DomainGetXmlDescRequest::new(dom, flags);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_GET_XML_DESC, pl).map(|resp| resp.into()))
    }

    /// Configure the domain to be automatically started when the host machine boots.
    pub fn set_autostart(&self, dom: &request::Domain, enable: bool) -> LibvirtFuture<()> {
        let pl = request::DomainSetAutoStartRequest::new(dom, enable);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_SET_AUTOSTART, pl).map(|resp| resp.into()))
    }

    /// Provides a boolean value indicating whether the domain configured to be automatically started when the host machine boots.
    pub fn get_autostart(&self, dom: &request::Domain) -> LibvirtFuture<bool> {
        let pl = request::DomainGetAutoStartRequest::new(dom);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_GET_AUTOSTART, pl).map(|resp| resp.into()))
    }

    /// Send key(s) to the guest.
    pub fn send_key(&self, dom: &request::Domain, codeset: u32, holdtime: u32, keycodes: Vec<u32>) -> LibvirtFuture<()> {
        let pl = request::DomainSendKeyRequest::new(dom, codeset, holdtime, keycodes, 0);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_SEND_KEY, pl).map(|resp| resp.into()))
    }

/*
    fn migrate_begin(&self, dom: &request::Domain, params: Vec<request::MigrationParam>, flags: request::DomainMigrateFlags::DomainMigrateFlags) -> LibvirtFuture<()> {
        let pl = request::MigrateBeginRequest::new(dom, params, flags);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_MIGRATE_BEGIN3_PARAMS, pl).map(|resp| {
            println!("DEBUG RESP: {:?}", resp);
        }))
    }
    */

    /// Performs unmanaged migration
    pub fn migrate(&self, dom: &request::Domain, uri: &str, params: Vec<request::MigrationParam>, flags: request::DomainMigrateFlags::DomainMigrateFlags) -> LibvirtFuture<()> {
        let pl = request::MigratePerformRequest::new(dom, Some(uri), params, vec![], flags);
        Box::new(self.client.request(request::remote_procedure::REMOTE_PROC_DOMAIN_MIGRATE_PERFORM3_PARAMS, pl).map(|resp| {
            println!("DEBUG RESP: {:?}", resp);
        }))
    }
}

impl Service for Client {
    type Request = LibvirtRequest;
    type Response = LibvirtResponse;
    type Error = ::std::io::Error;
    type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

    fn call(&self, req: Self::Request) -> Self::Future {
        Box::new(self.inner.call(req))
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use ::tokio_core::reactor::Core;
    use ::async::Client;
    use futures::{Future,IntoFuture,Stream};

    fn connect() -> (Client, Core) {
        let core = Core::new().unwrap();
        let handle = core.handle();
        let client = Client::connect("/var/run/libvirt/libvirt-sock", &handle).unwrap();
        (client, core)
    }

    fn run_connected<'a, P, F, I>(f: P)
     where P: FnOnce(Client) -> F,
           I: Debug,
           F: IntoFuture<Item=I, Error=::LibvirtError> + 'static {
        let (client, mut core) = connect();
        let result = core.run({
            client.auth()
           .and_then(|_| client.open())
           .and_then(|_| {
               let c = client.clone();
               f(c)
           })
        }).unwrap();
        println!("{:?}", result);
    }

    #[test]
    fn test_version() {
        run_connected(|client| client.version())
    }
}