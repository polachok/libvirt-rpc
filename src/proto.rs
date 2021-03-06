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

struct LibvirtCodec;

#[derive(Debug)]
pub struct LibvirtRequest {
    pub stream: Option<Sender<LibvirtResponse>>,
    pub sink: Option<Receiver<BytesMut>>,
    pub event: Option<request::remote_procedure>,
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
            header,
            payload,
        })))
    }
}

fn framed_delimited<T, C>(framed: length_delimited::Framed<T>, codec: C) -> FramedTransport<T, C>
    where T: AsyncRead + AsyncWrite, C: codec::Encoder + codec::Decoder
 {
    FramedTransport{ inner: framed, codec }
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
    sinks: HashMap<u64, (::futures::sync::mpsc::Receiver<BytesMut>, i32, bool)>,
}

impl<T> LibvirtTransport<T> where T: AsyncRead + AsyncWrite + 'static {
    fn is_event(&self, procedure: request::generated::remote_procedure) -> bool {
        if request::DomainEventId::from_procedure(procedure).is_some() {
            return true;
        }
        debug!("not event: procedure {:?}", procedure);
        false
    }

    fn poll_sinks(&mut self) -> Poll<Option<(RequestId, LibvirtRequest)>, <LibvirtSink as Sink>::SinkError> {
        use futures::Async;
        let mut result = Ok(Async::NotReady);

        debug!("POLL SINKS");
        for (req_id, &mut (ref mut sink, proc_, ref mut complete)) in self.sinks.iter_mut() {
            debug!("Processing sink {} proc: {} complete: {}", req_id, proc_, complete);
            match sink.poll() {
                Ok(Async::Ready(Some(buf))) => {
                    let req = LibvirtRequest {
                                stream: None,
                                sink: None,
                                event: None,
                                header: request::virNetMessageHeader {
                                    type_: ::request::generated::virNetMessageType::VIR_NET_STREAM,
                                    status: request::virNetMessageStatus::VIR_NET_CONTINUE,
                                    proc_,
                                    ..Default::default()
                                },
                                payload: buf,
                    };
                    return Ok(Async::Ready(Some((*req_id, req))));
                }

                Ok(Async::Ready(None)) => {
                    if *complete {
                        /* skip completed sinks */
                        continue;
                    }
                    let req = LibvirtRequest {
                        stream: None,
                        sink: None,
                        event: None,
                        header: request::virNetMessageHeader {
                            type_: ::request::generated::virNetMessageType::VIR_NET_STREAM,
                            status: request::virNetMessageStatus::VIR_NET_OK,
                            proc_,
                            ..Default::default()
                        },
                        payload: BytesMut::new(),
                    };
                    debug!("Empty sink {}, sending empty msg", req_id);
                    *complete = true;
                    result = Ok(Async::Ready(Some((*req_id, req))));
                    break;
                }

                Ok(Async::NotReady) => {
                    /* try next */
                }

                Err(e) => {
                    error!("Error in sink {}: {:?}", req_id, e);
                }
            }
        }

        result
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
            let req_id = u64::from(resp.header.serial);
            let mut remove_stream = false;

            if let Some(ref mut stream) = self.streams.get_mut(&req_id) {
                debug!("found stream for request id {}: {:?}", req_id, resp.header);
                let sender = stream;
                if !resp.payload.is_empty() {
                    if resp.header.status == request::generated::virNetMessageStatus::VIR_NET_ERROR {
                        debug!("got error from stream, should drop sink");
                        self.sinks.remove(&req_id);
                    }
                    let _ = sender.start_send(resp);
                    let _ = sender.poll_complete();
                } else {
                    debug!("closing stream {}", req_id);

                    debug!("got something from stream, should drop sink!");
                    self.sinks.remove(&req_id);

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
                debug!("Droppping stream ID {}", req_id);
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

        debug!("POLL CALLED");

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
        use futures::{AsyncSink};

        /*
        if self.buffer.is_some() {
            debug!("Found something in sink_buffer: NOT READY");
            return Ok(AsyncSink::NotReady(item));
        }
        */

        if let Some(event_proc) = mem::replace(&mut item.1.event, None) {
            debug!("Sending event request {:?}", event_proc);
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
                self.sinks.insert(item.0, (sink, item.1.header.proc_, false));
                new_sink = true;
            }
        }

        {
            debug!("Have {} sinks", self.sinks.len());
            if !new_sink && !self.sinks.is_empty() {
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
                AsyncSink::Ready => {
                    debug!("Sent buffered msg");
                },
            }
        }

        loop {
            match self.poll_sinks() {
                Ok(Async::Ready(Some(req))) => {
                    debug!("SEND: some sinks are ready, try processing");

                    debug!("Sending sink msg: {} {:?} pl: {}", req.0, req.1.header, req.1.payload.len());
                    match try!(self.inner.start_send(req)) {
                        AsyncSink::NotReady(item) => {
                            debug!("Inner not ready, putting sink msg back");
                            mem::replace(&mut self.buffer, Some(item));
                            return self.inner.poll_complete();
                        },
                        AsyncSink::Ready => {
                            debug!("Sent sink msg");
                        },
                    }
                }
                ret => {
                    debug!("POLL_SINKS: {:?}", ret);
                    break;
                }
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

pub struct EventStream<E> where E: request::DomainEvent {
    inner: ::futures::sync::mpsc::Receiver<LibvirtResponse>,
    handle_resp: fn(LibvirtResponse) -> Result<<E as request::DomainEvent>::From, ::LibvirtError>,
}

impl<E> EventStream<E> where E: request::DomainEvent {
    pub fn new(inner: ::futures::sync::mpsc::Receiver<LibvirtResponse>,
           handler: fn(LibvirtResponse) -> Result<<E as request::DomainEvent>::From, ::LibvirtError>) -> Self {
               EventStream { inner, handle_resp: handler }
    }

}

impl<E> Stream for EventStream<E> where E: ::std::fmt::Debug + request::DomainEvent {
    type Item = E;
    type Error = ::LibvirtError;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        use futures::Async;
        match self.inner.poll() {
            Ok(Async::Ready(Some(resp))) => {
                match (self.handle_resp)(resp) {
                    Ok(msg) => {
                        let msg = msg.into();
                        debug!("EVENT (CALLBACK) {:?}", msg);
                        Ok(Async::Ready(Some(msg)))
                    },
                    Err(e) => Err(e),
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
