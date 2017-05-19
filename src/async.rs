use std::io::Cursor;
use std::path::Path;
use std::marker::PhantomData;
use ::xdr_codec::{Pack,Unpack};
use ::bytes::{BufMut, Bytes, BytesMut, BigEndian};
use ::tokio_io::codec;
use ::tokio_io::{AsyncRead,AsyncWrite};
use ::tokio_io::codec::length_delimited;
use ::tokio_proto::multiplex::{self,RequestId};
use ::tokio_service::Service;
use ::request;
use ::LibvirtError;
use ::futures::{Stream, Sink, Poll, StartSend, Future, future};
use ::env_logger;

pub struct LibvirtCodec;

#[derive(Debug)]
pub enum LibvirtRequest {
    AuthListRequest,
    ConnectOpenRequest,
    LibVersionRequest,
}

#[derive(Debug)]
pub enum LibvirtResponse {
    AuthListResponse(request::AuthListResponse),
    ConnectOpenResponse(request::ConnectOpenResponse),
    LibVersionResponse(request::GetLibVersionResponse),
}

impl LibvirtRequest {
    fn encode(&self, serial: RequestId, buf: &mut BytesMut) -> Result<(), LibvirtError> {
        use self::LibvirtRequest::*;
        let mut writer = buf.writer();

        match self {
                &AuthListRequest => {
                    let packet = request::AuthListRequest::new(serial as u32);
                    try!(packet.pack(&mut writer));
                },
                &ConnectOpenRequest => {
                    let packet = request::ConnectOpenRequest::new(serial as u32);
                    try!(packet.pack(&mut writer));
                },
                &LibVersionRequest => {
                    let packet = request::GetLibVersionRequest::new(serial as u32);
                    try!(packet.pack(&mut writer));
                }
        }
        Ok(())
    }
}

impl LibvirtResponse {
    fn decode<R: ::std::io::Read>(proc_: i32, mut reader: R) -> Result<Self, LibvirtError> {
        let proc_num = proc_ as i16;
        let procedure: request::remote_procedure = unsafe { ::std::mem::transmute(proc_num) };
        let req = match procedure {
            request::remote_procedure::REMOTE_PROC_AUTH_LIST => {
                let (req, _) = try!(request::AuthListResponse::unpack(&mut reader));
                LibvirtResponse::AuthListResponse(req)
            },
            request::remote_procedure::REMOTE_PROC_CONNECT_OPEN => {
                let (req, _) = try!(request::ConnectOpenResponse::unpack(&mut reader));
                LibvirtResponse::ConnectOpenResponse(req)
            },
            request::remote_procedure::REMOTE_PROC_CONNECT_GET_LIB_VERSION => {
                let (req, _) = try!(request::GetLibVersionResponse::unpack(&mut reader));
                LibvirtResponse::LibVersionResponse(req)
            },
            _ => unimplemented!(),
        };
        Ok(req)
    }
}

impl codec::Encoder for LibvirtCodec {
    type Item = (RequestId, LibvirtRequest);
    type Error = ::std::io::Error; //LibvirtError;

    fn encode(&mut self, msg: (RequestId, LibvirtRequest), buf: &mut BytesMut) -> Result<(), Self::Error> {
        use ::std::io::ErrorKind;
        msg.1.encode(msg.0, buf).map_err(|e| ::std::io::Error::new(ErrorKind::InvalidInput, e.to_string()))
    }
}

impl codec::Decoder for LibvirtCodec {
    type Item = (RequestId, LibvirtResponse);
    type Error = ::std::io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        use ::std::io::ErrorKind;
        let mut reader = Cursor::new(buf);
        let (header, _) = try!(request::virNetMessageHeader::unpack(&mut reader)
                                    .map_err(|e| ::std::io::Error::new(ErrorKind::InvalidInput, "fuck")));
        let resp = try!(LibvirtResponse::decode(header.proc_, &mut reader)
                                    .map_err(|e| ::std::io::Error::new(ErrorKind::InvalidInput, "fuck")));
        Ok(Some((header.serial as RequestId, resp)))
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

pub struct Client {
    inner: multiplex::ClientService<::tokio_uds::UnixStream, LibvirtProto>,
}

impl Client {
    pub fn connect<P: AsRef<Path>>(path: P, handle: &::tokio_core::reactor::Handle) -> Result<Client, ::std::io::Error> {
        use ::tokio_uds_proto::UnixClient;
        UnixClient::new(LibvirtProto)
                .connect(path, handle)
                .map(|inner| Client { inner })
    }

    pub fn auth(&self) -> <Self as Service>::Future {
        use self::LibvirtRequest::*;
        self.inner.call(AuthListRequest).boxed()
    }

    pub fn open(&self) -> <Self as Service>::Future {
        use self::LibvirtRequest::*;
        self.inner.call(ConnectOpenRequest).boxed()
    }

    pub fn version(&self) -> <Self as Service>::Future {
        use self::LibvirtRequest::*;
        self.inner.call(LibVersionRequest).boxed()
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
    }).unwrap();
    println!("{:?}", result);
    match result {
        LibvirtResponse::LibVersionResponse(payload) => {
            println!("version: {}", payload.version())
        },
        _ => unimplemented!(),
    }
}