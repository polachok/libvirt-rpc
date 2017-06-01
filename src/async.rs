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
use ::tokio_io::codec;
use ::tokio_io::{AsyncRead, AsyncWrite};
use ::tokio_io::codec::length_delimited;
use ::tokio_proto::multiplex::{self, RequestId};
use ::tokio_service::Service;
use ::request;
use ::LibvirtError;
use ::futures::{Stream, Sink, Poll, StartSend, Future, future};

struct LibvirtCodec;

#[derive(Debug,Clone)]
pub struct LibvirtRequest {
    header: request::virNetMessageHeader,
    payload: BytesMut,
}

#[derive(Debug,Clone)]
pub struct LibvirtResponse {
    header: request::virNetMessageHeader,
    payload: BytesMut,
}

impl codec::Encoder for LibvirtCodec {
    type Item = (RequestId, LibvirtRequest);
    type Error = ::std::io::Error;

    fn encode(&mut self, msg: (RequestId, LibvirtRequest), buf: &mut BytesMut) -> Result<(), Self::Error> {
        use ::std::io::ErrorKind;
        let mut req = msg.1;
        let buf = {
            let mut writer = buf.writer();
            req.header.serial = msg.0 as u32;
            try!(req.header.pack(&mut writer).map_err(|e| ::std::io::Error::new(ErrorKind::InvalidInput, e.to_string())));
            writer.into_inner()
        };
        buf.reserve(req.payload.len());
        buf.put(req.payload);
        Ok(())
    }
}

impl codec::Decoder for LibvirtCodec {
    type Item = (RequestId, LibvirtResponse);
    type Error = ::std::io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        use ::std::io::ErrorKind;
        let (header, hlen, buf) = {
            let mut reader = Cursor::new(buf);
            let (header, hlen) = try!(request::virNetMessageHeader::unpack(&mut reader)
                                        .map_err(|e| ::std::io::Error::new(ErrorKind::InvalidInput, e.to_string())));
            (header, hlen, reader.into_inner())
        };
        let payload = buf.split_off(hlen);
        Ok(Some((header.serial as RequestId, LibvirtResponse {
            header: header,
            payload: payload,
        })))
    }
}

fn framed_delimited<T, C>(framed: length_delimited::Framed<T>, codec: C) -> FramedTransport<T, C>
    where T: AsyncRead + AsyncWrite, C: codec::Encoder + codec::Decoder
 {
    FramedTransport{ inner: framed, codec: codec }
}

struct FramedTransport<T, C> where T: AsyncRead + AsyncWrite + 'static {
    inner: length_delimited::Framed<T>,
    codec: C,
}

impl<T, C> Stream for FramedTransport<T, C> where
                T: AsyncRead + AsyncWrite, C: codec::Decoder,
                ::std::io::Error: ::std::convert::From<<C as ::tokio_io::codec::Decoder>::Error> {
    type Item = <C as codec::Decoder>::Item;
    type Error = <C as codec::Decoder>::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        use futures::Async;
        let codec = &mut self.codec;
        self.inner.poll().and_then(|async| {
            match async {
                Async::Ready(Some(mut buf)) => {
                    let pkt = try!(codec.decode(&mut buf));
                    Ok(Async::Ready(pkt))
                },
                Async::Ready(None) => {
                    Ok(Async::Ready(None))
                },
                Async::NotReady => {
                    Ok(Async::NotReady)
                }
            }
        }).map_err(|e| e.into())
    }
}

impl<T, C> Sink for FramedTransport<T, C> where
        T: AsyncRead + AsyncWrite + 'static,
        C: codec::Encoder + codec::Decoder,
        ::std::io::Error: ::std::convert::From<<C as ::tokio_io::codec::Encoder>::Error> {
    type SinkItem = <C as codec::Encoder>::Item;
    type SinkError = <C as codec::Encoder>::Error;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        use futures::AsyncSink;
        let codec = &mut self.codec;
        let mut buf = BytesMut::with_capacity(64);
        try!(codec.encode(item, &mut buf));
        assert!(try!(self.inner.start_send(buf)).is_ready());
        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.inner.poll_complete().map_err(|e| e.into())
    }

    fn close(&mut self) -> Poll<(), Self::SinkError> {
        try_ready!(self.poll_complete().map_err(|e| e.into()));
        self.inner.close().map_err(|e| e.into())
    }
}

struct LibvirtTransport<T> where T: AsyncRead + AsyncWrite + 'static {
    inner: FramedTransport<T, LibvirtCodec>,
    events: Arc<Mutex<HashMap<i32, ::futures::sync::mpsc::Sender<::request::DomainEvent>>>>,
}

impl<T> LibvirtTransport<T> where T: AsyncRead + AsyncWrite + 'static {
    fn process_event(&self, resp: &LibvirtResponse) -> ::std::io::Result<bool> {
        let procedure = unsafe { ::std::mem::transmute(resp.header.proc_ as u16) };
        match procedure {
            request::remote_procedure::REMOTE_PROC_DOMAIN_EVENT_CALLBACK_LIFECYCLE => {
                let msg = {
                    let mut cursor = Cursor::new(&resp.payload);
                    let (msg, _) = request::generated::remote_domain_event_callback_lifecycle_msg::unpack(&mut cursor).unwrap();
                    debug!("LIFECYCLE EVENT (CALLBACK) PL: {:?}", msg);
                    msg
                };
                {
                    let mut map = self.events.lock().unwrap();
                    if let Some(sender) = map.get_mut(&msg.callbackID) {
                        use std::io::ErrorKind;
                        try!(sender.start_send(msg.into()).map_err(|e| ::std::io::Error::new(ErrorKind::InvalidInput, e.to_string())));
                        try!(sender.poll_complete().map_err(|e| ::std::io::Error::new(ErrorKind::InvalidInput, e.to_string())));
                    }
                }
                return Ok(true);
            },
            _ => {
                debug!("unknown procedure {:?} in {:?}", procedure, resp);
            },
        }
        Ok(false)
    }
}

impl<T> Stream for LibvirtTransport<T> where
    T: AsyncRead + AsyncWrite + 'static,
 {
    type Item = (RequestId, LibvirtResponse);
    type Error = ::std::io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        use futures::Async;
        match self.inner.poll() {
            Ok(async) => {
                match async {
                Async::Ready(Some((id, ref resp))) => {
                    debug!("FRAME READY ID: {} RESP: {:?}", id, resp);
                    if try!(self.process_event(resp)) {
                            debug!("processed event, get next packet");
                            return self.poll();
                    }
                },
                _ => debug!("{:?}", async),
                }
                debug!("RETURNING {:?}", async);
                Ok(async)
            },
            Err(e) => Err(e),
        }
    }
}

impl<T> Sink for LibvirtTransport<T> where
    T: AsyncRead + AsyncWrite + 'static,
 {
    type SinkItem = (RequestId, LibvirtRequest);
    type SinkError = ::std::io::Error;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        self.inner.start_send(item)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.inner.poll_complete()
    }

    fn close(&mut self) -> Poll<(), Self::SinkError> {
        self.inner.close()
    }
}

#[derive(Debug, Clone)]
struct LibvirtProto {
    events: Arc<Mutex<HashMap<i32, ::futures::sync::mpsc::Sender<::request::DomainEvent>>>>,
}

impl<T> multiplex::ClientProto<T> for LibvirtProto where T: AsyncRead + AsyncWrite + 'static {
    type Request = LibvirtRequest;
    type Response = LibvirtResponse;
    type Transport = LibvirtTransport<T>;
    type BindTransport = Result<Self::Transport, ::std::io::Error>;

    fn bind_transport(&self, io: T) -> Self::BindTransport {
        let framed = length_delimited::Builder::new()
                        .big_endian()
                        .length_field_offset(0)
                        .length_field_length(4)
                        .length_adjustment(-4)
                        .new_framed(io);
        Ok(LibvirtTransport{ 
            inner: framed_delimited(framed, LibvirtCodec),
            events: self.events.clone(),
        })
    }
}

pub struct EventStream<T> {
    inner: ::futures::sync::mpsc::Receiver<T>,
}

impl<T> Stream for EventStream<T> {
    type Item = T;
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        self.inner.poll()
    }
}

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
        let proto = LibvirtProto { events: events.clone() };
        UnixClient::new(proto)
                .connect(path, handle)
                .map(|inner| Client { inner: Arc::new(Mutex::new(inner)), events: events.clone() })
    }

    fn pack<P: Pack<::bytes::Writer<::bytes::BytesMut>>>(procedure: request::remote_procedure, payload: P) -> Result<LibvirtRequest, ::xdr_codec::Error> {
        let buf = BytesMut::with_capacity(1024);
        let buf = {
            let mut writer = buf.writer();
            try!(payload.pack(&mut writer));
            writer.into_inner()
        };
        let req = LibvirtRequest {
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
        let req = Self::pack(procedure, payload);
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
fn such_async() {
    use ::tokio_core::reactor::Core;

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
                client.domain().register_event(&dom, 0)
            }).and_then(|events| {
                handle.spawn(events.for_each(|ev| {
                    println!("EVENT {:?}", ev);
                    Ok(())
                }));
                Ok(())
            })
    }).unwrap();
    println!("RESULT {:?}", result);
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