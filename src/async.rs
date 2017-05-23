//! This module provides tokio based async interface to libvirt API
use std::io::Cursor;
use std::path::Path;
use std::collections::{HashMap,VecDeque};
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

pub struct LibvirtCodec;

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
    fn process_event(&self, resp: &LibvirtResponse) -> bool {
        let procedure = unsafe { ::std::mem::transmute(resp.header.proc_ as u16) };
        match procedure {
            request::remote_procedure::REMOTE_PROC_DOMAIN_EVENT_CALLBACK_LIFECYCLE => {
                //debug!("LIFECYCLE EVENT (CALLBACK) ID: {} RESP: {:?}", id, resp);
                let msg = {
                    let mut cursor = Cursor::new(&resp.payload);
                    let (msg, _) = request::generated::remote_domain_event_callback_lifecycle_msg::unpack(&mut cursor).unwrap();
                    debug!("LIFECYCLE EVENT (CALLBACK) PL: {:?}", msg);
                    msg
                };
                {
                    let mut map = self.events.lock().unwrap();
                    if let Some(sender) = map.get_mut(&msg.callbackID) {
                        sender.start_send(msg.into());
                        sender.poll_complete();
                    }
                }
                return true;
            },
            _ => {
                debug!("SOMETHING RESP: {:?}", resp);
            },
        }
        false
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
                    debug!("SOMETHING READY ID: {} RESP: {:?}", id, resp);
                    if self.process_event(resp) {
                            return self.poll();
                    }
                    /*
                    let procedure = unsafe { ::std::mem::transmute(resp.header.proc_ as u16) };
                    match procedure {
                        request::remote_procedure::REMOTE_PROC_DOMAIN_EVENT_CALLBACK_LIFECYCLE => {
                            //debug!("LIFECYCLE EVENT (CALLBACK) ID: {} RESP: {:?}", id, resp);
                            let cbid = {
                                let mut cursor = Cursor::new(&resp.payload);
                                let (msg, _) = request::generated::remote_domain_event_callback_lifecycle_msg::unpack(&mut cursor).unwrap();
                                debug!("LIFECYCLE EVENT (CALLBACK) ID: {} PL: {:?}", id, msg);
                                msg.callbackID
                            };
                            {
                                let mut map = self.events.lock().unwrap();
                                if let Some(sender) = map.get_mut(&cbid) {
                                    sender.start_send(resp.clone());
                                    sender.poll_complete();
                                }
                            }
                            return self.poll();
                        },
                        _ => {
                            debug!("SOMETHING ID: {} RESP: {:?}", id, resp);
                        },
                    }
                    */
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
pub struct Client {
    events: Arc<Mutex<HashMap<i32, ::futures::sync::mpsc::Sender<::request::DomainEvent>>>>,
    inner: multiplex::ClientService<::tokio_uds::UnixStream, LibvirtProto>,
}

impl Client {
    /// opens libvirt connection over unix socket
    pub fn connect<P: AsRef<Path>>(path: P, handle: &::tokio_core::reactor::Handle) -> Result<Client, ::std::io::Error> {
        use ::tokio_uds_proto::UnixClient;
        let events = Arc::new(Mutex::new(HashMap::new()));
        let proto = LibvirtProto { events: events.clone() };
        UnixClient::new(proto)
                .connect(path, handle)
                .map(|inner| Client { inner: inner, events: events.clone() })
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

    /// Collect a possibly-filtered list of all domains, and return an allocated array of information for each. 
    pub fn list(&self, flags: request::ListAllDomainsFlags) -> ::futures::BoxFuture<Vec<request::Domain>, LibvirtError> {
        let payload = request::ListAllDomainsRequest::new(flags);
        self.request(request::remote_procedure::REMOTE_PROC_CONNECT_LIST_ALL_DOMAINS, payload).map(|resp| resp.into()).boxed()
    }

    /// Try to lookup a domain on the given hypervisor based on its UUID.
    pub fn lookup_by_uuid(&self, uuid: &::uuid::Uuid) -> ::futures::BoxFuture<request::Domain, LibvirtError> {
        let pl = request::DomainLookupByUuidRequest::new(uuid);
        self.request(request::remote_procedure::REMOTE_PROC_DOMAIN_LOOKUP_BY_UUID, pl).map(|resp| resp.domain()).boxed()
    }

    pub fn register_event(&self, dom: &request::Domain, event: i32) -> ::futures::BoxFuture<EventStream<::request::DomainEvent>, LibvirtError> {
        let pl = request::DomainEventCallbackRegisterAnyRequest::new(event, dom);
        let map = self.events.clone();
        self.request(request::remote_procedure::REMOTE_PROC_CONNECT_DOMAIN_EVENT_CALLBACK_REGISTER_ANY, pl)
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
}

impl Service for Client {
    type Request = LibvirtRequest;
    type Response = LibvirtResponse;
    type Error = ::std::io::Error;
    type Future = ::futures::BoxFuture<Self::Response, Self::Error>;

    fn call(&self, req: Self::Request) -> Self::Future {
        self.inner.call(req).boxed()
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
            //.and_then(|_| client.register(0))
            .and_then(|_| client.version())
            .and_then(|_| client.list(request::DOMAINS_ACTIVE | request::DOMAINS_INACTIVE))
            .and_then(|_| client.lookup_by_uuid(&uuid))
            .and_then(|dom| {
                client.register_event(&dom, 0)
            }).and_then(|events| {
                handle.spawn(events.for_each(|ev| {
                    println!("EVENT {:?}", ev);
                    Ok(())
                }));
                Ok(())
            })
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