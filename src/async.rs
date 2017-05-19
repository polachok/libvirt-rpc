//! This module provides tokio based async interface to libvirt API
use std::io::Cursor;
use std::path::Path;
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

#[derive(Debug)]
pub struct LibvirtRequest {
    header: request::virNetMessageHeader,
    payload: BytesMut,
}

#[derive(Debug)]
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

type LibvirtTransport<T> = FramedTransport<T, LibvirtCodec>;

struct LibvirtProto;

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
        Ok(framed_delimited(framed, LibvirtCodec))
    }
}

/// Libvirt client
pub struct Client {
    inner: multiplex::ClientService<::tokio_uds::UnixStream, LibvirtProto>,
}

impl Client {
    /// opens libvirt connection over unix socket
    pub fn connect<P: AsRef<Path>>(path: P, handle: &::tokio_core::reactor::Handle) -> Result<Client, ::std::io::Error> {
        use ::tokio_uds_proto::UnixClient;
        UnixClient::new(LibvirtProto)
                .connect(path, handle)
                .map(|inner| Client { inner })
    }

    fn pack<P: Pack<::bytes::Writer<::bytes::BytesMut>>>(procedure: request::remote_procedure, payload: P) -> Result<LibvirtRequest, ::xdr_codec::Error> {
        let buf = BytesMut::with_capacity(100);
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

    fn request<P, U>(&self, procedure: request::remote_procedure, payload: P) -> ::futures::BoxFuture<U, LibvirtError>
        where P: Pack<::bytes::Writer<::bytes::BytesMut>>, U: Unpack<Cursor<::bytes::BytesMut>> + Send + 'static
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
        self.request(request::remote_procedure::REMOTE_PROC_AUTH_LIST, ())
    }

    /// opens up a read-write connection to the system qemu hypervisor driver
    pub fn open(&self) -> ::futures::BoxFuture<request::ConnectOpenResponse, LibvirtError> {
        let pl = request::ConnectOpenRequest::new();
        self.request(request::remote_procedure::REMOTE_PROC_CONNECT_OPEN, pl)
    }

    /// can be used to obtain the version of the libvirt software in use on the host
    pub fn version(&self) -> ::futures::BoxFuture<request::GetLibVersionResponse, LibvirtError> {
        self.request(request::remote_procedure::REMOTE_PROC_CONNECT_GET_LIB_VERSION, ())
    }

    pub fn list(&self) -> ::futures::BoxFuture<request::ListAllDomainsResponse, LibvirtError> {
        let payload = request::ListAllDomainsRequest::new(3);
        self.request(request::remote_procedure::REMOTE_PROC_CONNECT_LIST_ALL_DOMAINS, payload)
    }
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

    let mut core = Core::new().unwrap();
    let handle = core.handle(); 
    let client = Client::connect("/var/run/libvirt/libvirt-sock", &handle).unwrap();
    let result = core.run({
        client.auth()
            .and_then(|_| client.open())
            .and_then(|_| client.version())
            .and_then(|_| client.list())
    }).unwrap();
    println!("{:?}", result);
}