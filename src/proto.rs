use std::io::Cursor;
use std::collections::HashMap;
use ::xdr_codec::{Pack,Unpack};
use ::bytes::{BufMut, BytesMut};
use ::tokio_io::codec;
use ::tokio_io::{AsyncRead, AsyncWrite};
use ::tokio_io::codec::length_delimited;
use ::tokio_proto::multiplex::{self, RequestId};
use ::request;
use ::futures::{Stream, Sink, Poll, StartSend};
use ::futures::sync::mpsc::{Sender,Receiver};
use std::marker::PhantomData;

struct LibvirtCodec;

#[derive(Debug)]
pub struct LibvirtRequest {
    pub stream: Option<Sender<LibvirtResponse>>,
    pub sink: Option<Receiver<BytesMut>>,
    pub header: request::virNetMessageHeader,
    pub payload: BytesMut,
}

#[derive(Debug,Clone)]
pub struct LibvirtResponse {
    pub header: request::virNetMessageHeader,
    pub payload: BytesMut,
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
        use futures::{Async,AsyncSink};

        if let Ok(Async::NotReady) = self.poll_complete() {
            return Ok(AsyncSink::NotReady(item))
        }

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

pub struct LibvirtTransport<T> where T: AsyncRead + AsyncWrite + 'static {
    /* store here if underlying transport is not ready */
    buffer: Option<(RequestId, LibvirtRequest)>,
    inner: FramedTransport<T, LibvirtCodec>,
    /* procedure -> event stream */
    events: HashMap<u16, ::futures::sync::mpsc::Sender<LibvirtResponse>>,
    /* req.id -> stream */
    streams: HashMap<u64, ::futures::sync::mpsc::Sender<LibvirtResponse>>,
    /* req.id -> (stream, procedure) */
    sinks: HashMap<u64, (::futures::sync::mpsc::Receiver<BytesMut>, i32)>,
}

impl<T> LibvirtTransport<T> where T: AsyncRead + AsyncWrite + 'static {
    fn is_event_register(&self, procedure: request::generated::remote_procedure) -> Option<request::generated::remote_procedure> {
        match procedure {
            request::remote_procedure::REMOTE_PROC_CONNECT_DOMAIN_EVENT_CALLBACK_REGISTER_ANY => {
                Some(request::remote_procedure::REMOTE_PROC_DOMAIN_EVENT_CALLBACK_LIFECYCLE)
            },
            _ => None,
        }
    }

    fn is_event(&self, procedure: request::generated::remote_procedure) -> bool {
        match procedure {
            request::remote_procedure::REMOTE_PROC_DOMAIN_EVENT_CALLBACK_LIFECYCLE => {
                true
            },
            _ => {
                debug!("not event: procedure {:?}", procedure);
                false
            },
        }
    }

    fn process_sinks(&mut self) -> StartSend<(RequestId, LibvirtRequest), ::std::io::Error> {
        use futures::Async;
        use futures::AsyncSink;
        let mut sinks_to_drop = Vec::new();

        debug!("PROCESSING SINKS: count {}", self.sinks.len());

        for (req_id, &mut (ref mut sink, proc_)) in self.sinks.iter_mut() {
            debug!("Processing sink {}", req_id);
            let mut total_len = 0;
            let mut count = 0;
            'out: for _ in 0..100 {
                match sink.poll() {
                    Ok(Async::Ready(Some(buf))) => {
                        let len = buf.len();
                        let req = LibvirtRequest {
                            stream: None,
                            sink: None,
                            header: request::virNetMessageHeader {
                                type_: ::request::generated::virNetMessageType::VIR_NET_STREAM,
                                status: request::virNetMessageStatus::VIR_NET_CONTINUE,
                                proc_: proc_,
                                ..Default::default()
                            },
                            payload: buf,
                        };
                        debug!("Sink sending {:?}", req.header);
                        match self.inner.start_send((*req_id, req)) {
                            Ok(AsyncSink::NotReady(item)) => {
                                debug!("Inner not ready, sink {} processed {} of payload ({} messages) so far", req_id, total_len, count);
                                return Ok(AsyncSink::NotReady(item));
                            },
                            Ok(AsyncSink::Ready) => {
                                debug!("Sink sent");
                                count += 1;
                                total_len += len;
                            },
                            Err(e) => {
                                return Err(e);
                            }
                        }
                    },
                    Ok(Async::Ready(None)) => {
                        sinks_to_drop.push(*req_id);
                        let req = LibvirtRequest {
                            stream: None,
                            sink: None,
                            header: request::virNetMessageHeader {
                                type_: ::request::generated::virNetMessageType::VIR_NET_STREAM,
                                status: request::virNetMessageStatus::VIR_NET_OK,
                                proc_: proc_,
                                ..Default::default()
                            },
                            payload: BytesMut::new(),
                        };
                        debug!("Empty sink, sending empty msg");
                        let _ = self.inner.start_send((*req_id, req));
                        break 'out;
                    }
                    Ok(Async::NotReady) => {
                        debug!("Sink not ready yet");
                        break 'out;
                    },
                    _ => {
                        break 'out;
                    },
                }
            }
            debug!("Sink {} processed {} of payload ({} messages)", req_id, total_len, count);
        }

        for id in sinks_to_drop {
            self.sinks.remove(&id);
        }
        debug!("All sinks empty, returning would block");
        Err(::std::io::Error::new(::std::io::ErrorKind::WouldBlock, "sinks empty"))
    }

    fn process_event(&mut self, resp: LibvirtResponse) {
        let proc_ = resp.header.proc_ as u16;

        if let Some(ref mut stream) = self.events.get_mut(&proc_) {
            debug!("Event: found event stream for proc {}", proc_);
            let sender = stream;
            let _ = sender.start_send(resp);
            let _ = sender.poll_complete();
            return
        }
        debug!("Event: can't find event stream id for proc {}", proc_);
    }

    fn process_stream(&mut self, resp: LibvirtResponse) {
        debug!("incoming stream: {:?}", resp.header);
        {
            let req_id = resp.header.serial as u64;
            let mut remove_stream = false;

            if let Some(ref mut stream) = self.streams.get_mut(&req_id) {
                debug!("found stream for request id {}: {:?}", req_id, resp.header);
                let sender = stream;
                if resp.payload.len() != 0 {
                    if resp.header.status == request::generated::virNetMessageStatus::VIR_NET_ERROR {
                        debug!("got error from stream, should drop sink");
                        self.sinks.remove(&req_id);
                    }
                    let _ = sender.start_send(resp);
                    let _ = sender.poll_complete();
                } else {
                    debug!("closing stream {}", req_id);
                    let _ = sender.start_send(resp);
                    let _ = sender.close();
                    let _ = sender.poll_complete();
                    remove_stream = true;
                }
            } else {
                error!("can't find stream for request id {}: {:?}", req_id, resp.header);
                if resp.header.status == request::generated::virNetMessageStatus::VIR_NET_ERROR {
                    let mut reader = Cursor::new(resp.payload);
                    let (err, _) = request::virNetMessageError::unpack(&mut reader).unwrap();
                    println!("ERROR: {:?}", err);
                }
            }
            if remove_stream {
                self.streams.remove(&req_id);
            }
        }
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
                Async::Ready(Some((id, resp))) => {
                    debug!("FRAME READY ID: {} RESP: {:?}", id, resp);

                    let procedure = unsafe { ::std::mem::transmute(resp.header.proc_ as u16) };
                    if self.is_event(procedure) {
                        debug!("event received!");
                        self.process_event(resp);
                        debug!("processed event msg, get next packet");
                        return self.poll();
                    }

                    if resp.header.type_ == request::generated::virNetMessageType::VIR_NET_STREAM {
                        self.process_stream(resp);
                        debug!("processed stream msg, get next packet");
                        return self.poll();
                    }

                    return Ok(Async::Ready(Some((id, resp))));
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

    fn start_send(&mut self, mut item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        use ::std::mem;
        use futures::AsyncSink;

        let procedure = unsafe { ::std::mem::transmute(item.1.header.proc_ as u16) };
        if let Some(event_proc) = self.is_event_register(procedure) {
            debug!("Sending event request {:?}/{}", procedure, procedure as u16);
            if let Some(stream) = mem::replace(&mut item.1.stream, None) {
                self.events.insert(event_proc as u16, stream);
            }
        }

        if let Some(stream) = mem::replace(&mut item.1.stream, None) {
            debug!("SENDING REQ ID = {} {:?} WITH STREAM", item.0, item.1.header);
            self.streams.insert(item.0, stream);
        }

        let mut new_sink = false;
        if let Some(sink) = mem::replace(&mut item.1.sink, None) {
            debug!("SENDING REQ ID = {} {:?} WITH SINK", item.0, item.1.header);
            {
                self.sinks.insert(item.0, (sink, item.1.header.proc_));
                new_sink = true;
            }
        }

        {
            debug!("Have {} sinks", self.sinks.len());
            if !new_sink && self.sinks.len() > 0 {
                return Ok(AsyncSink::NotReady(item));
            }
        }
        self.inner.start_send(item)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        use futures::{Async,AsyncSink};
        use std::mem;
        debug!("POLL COMPLETE CALLED");

        if let Some(req) = mem::replace(&mut self.buffer, None) {
            debug!("Sending buffered msg");
            match try!(self.inner.start_send(req)) {
                AsyncSink::NotReady(item) => {
                    debug!("Inner not ready, putting buffered msg back");
                    mem::replace(&mut self.buffer, Some(item));
                    return self.inner.poll_complete();
                },
                AsyncSink::Ready => {},
            }
        }
        loop {
            {
                if self.sinks.len() == 0 {
                    break;
                }
            }
            match self.process_sinks() {
                Ok(AsyncSink::NotReady(pkt)) => {
                    debug!("Sink reports things not ready, saving msg in buffer");
                    mem::replace(&mut self.buffer, Some(pkt));
                    return self.inner.poll_complete();
                }
                Err(ref e) if e.kind() == ::std::io::ErrorKind::WouldBlock => {
                    debug!("Sinks empty (would block)");
                    break;
                }
                _ => {},
            }
        }
        self.inner.poll_complete()
    }

    fn close(&mut self) -> Poll<(), Self::SinkError> {
        self.inner.close()
    }
}

#[derive(Debug, Clone)]
pub struct LibvirtProto;

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
            buffer: None,
            inner: framed_delimited(framed, LibvirtCodec),
            events: HashMap::new(),
            streams: HashMap::new(),
            sinks: HashMap::new(),
        })
    }
}

pub struct EventStream<T> {
    pub inner: ::futures::sync::mpsc::Receiver<LibvirtResponse>,
    _phantom: PhantomData<T>,
}

impl<T> From<::futures::sync::mpsc::Receiver<LibvirtResponse>> for EventStream<T> {
    fn from(r: ::futures::sync::mpsc::Receiver<LibvirtResponse>) -> Self {
        EventStream {
            inner: r, 
            _phantom: PhantomData,
        }
    }
}

impl<U: From<request::generated::remote_domain_event_callback_lifecycle_msg> + ::std::fmt::Debug> Stream for EventStream<U> {
    type Item = U;
    type Error = ::LibvirtError;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        use futures::Async;
        match self.inner.poll() {
            Ok(Async::Ready(Some(resp))) => {
                let procedure = unsafe { ::std::mem::transmute(resp.header.proc_ as u16) };
                match procedure {
                    request::remote_procedure::REMOTE_PROC_DOMAIN_EVENT_CALLBACK_LIFECYCLE => {
                        let mut cursor = Cursor::new(resp.payload);
                        let (msg, _) = request::generated::remote_domain_event_callback_lifecycle_msg::unpack(&mut cursor).unwrap();
                        let msg = msg.into();
                        debug!("LIFECYCLE EVENT (CALLBACK) {:?} {:?}", resp.header, msg);
                        Ok(Async::Ready(Some(msg)))
                    },
                    _ => {
                        error!("UNKNOWN EVENT RECEIVED {:?}", procedure);
                        Ok(Async::NotReady)
                    },
                }
            },
            Ok(Async::Ready(None)) => Ok(Async::Ready(None)),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(e) => panic!(e),
        }
    }
}

pub struct LibvirtStream {
    inner: ::futures::sync::mpsc::Receiver<LibvirtResponse>,
}

impl From<::futures::sync::mpsc::Receiver<LibvirtResponse>> for LibvirtStream {
    fn from(f: ::futures::sync::mpsc::Receiver<LibvirtResponse>) -> Self {
        LibvirtStream{ inner: f }
    }
}

impl Stream for LibvirtStream {
    type Item = BytesMut;
    type Error = ::LibvirtError;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        use futures::Async;
        match self.inner.poll() {
            Ok(Async::Ready(Some(resp))) => {
                if resp.header.status == request::generated::virNetMessageStatus::VIR_NET_ERROR {
                    let mut reader = Cursor::new(resp.payload);
                    let (err, _) = request::virNetMessageError::unpack(&mut reader).unwrap();
                    return Err(::LibvirtError::from(err));
                }
                Ok(Async::Ready(Some(resp.payload)))
            },
            Ok(Async::Ready(None)) => Ok(Async::Ready(None)),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(e) => panic!("LibvirtStream: unexpected error from mpsc::receiver: {:?}", e),
        }
    }
}

pub struct LibvirtSink {
    pub inner: ::futures::sync::mpsc::Sender<BytesMut>,
}

impl Sink for LibvirtSink {
    type SinkItem = BytesMut;
    type SinkError = ::futures::sync::mpsc::SendError<Self::SinkItem>;

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

impl Drop for LibvirtSink {
    fn drop(&mut self) {
        debug!("LibvirtSink dropping");
        let _ = self.close();
        let _ = self.poll_complete();
    }
}