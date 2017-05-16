use std::io;
use std::io::Cursor;
use std::path::Path;
use ::xdr_codec::{Pack,Unpack};
use ::bytes::{BufMut,BytesMut,ByteOrder,BigEndian};
use ::tokio_io::codec;
use ::tokio_io::{AsyncRead,AsyncWrite};
use ::tokio_io::codec::length_delimited;
use ::tokio_proto::multiplex::{self,RequestId};
use ::tokio_service::Service;
use ::request;
use ::LibvirtError;
use ::futures::{Stream, Sink, Poll, StartSend, Future, future};

type LibvirtFrame<T> = (RequestId, T);

pub struct LibvirtCodec;

#[derive(Debug)]
pub enum LibvirtMessage {
    AuthListRequest,
}

impl LibvirtMessage {
    fn encode(&self, serial: RequestId, buf: &mut BytesMut) -> Result<(), LibvirtError> {
        let mut writer = buf.writer();
        match self {
                &self::LibvirtMessage::AuthListRequest => {
                    let packet = request::AuthListRequest::new(serial as u32);
                    try!(packet.pack(&mut writer));
                },
        }
        Ok(())
    }
}

impl codec::Encoder for LibvirtCodec {
    type Item = (RequestId, LibvirtMessage);
    type Error = ::std::io::Error; //LibvirtError;

    fn encode(&mut self, msg: (RequestId, LibvirtMessage), buf: &mut BytesMut) -> Result<(), Self::Error> {
        use ::std::io::ErrorKind;
        msg.1.encode(msg.0, buf).map_err(|e| ::std::io::Error::new(ErrorKind::InvalidInput, "fuck"))
    }
}

impl codec::Decoder for LibvirtCodec {
    type Item = (RequestId, LibvirtMessage);
    type Error = ::std::io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        use ::std::io::ErrorKind;
        use bytes::IntoBuf;
        println!("DECODING");
        let mut reader = Cursor::new(buf);
        let (header, hlen) = try!(request::virNetMessageHeader::unpack(&mut reader)
                                    .map_err(|e| ::std::io::Error::new(ErrorKind::InvalidInput, "fuck")));
        println!("Header: {:?}", header);
        unimplemented!()
    }
}

struct LibvirtProto;

struct LibvirtTransport<T> {
    inner: length_delimited::Framed<T>,
}

impl<T> multiplex::ClientProto<T> for LibvirtProto where T: AsyncRead + AsyncWrite + 'static {
    type Request = LibvirtMessage;
    type Response = LibvirtMessage;
    type Transport = LibvirtTransport<T>;
    type BindTransport = Result<Self::Transport, ::std::io::Error>;
    fn bind_transport(&self, io: T) -> Self::BindTransport {
        let framed = length_delimited::Builder::new()
                        .big_endian()
                        .length_field_offset(0)
                        .length_field_length(4)
                        .length_adjustment(-4)
                        .new_framed(io);
        Ok(LibvirtTransport{ inner: framed })
    }
}

impl<T> Stream for LibvirtTransport<T> where T: AsyncRead + AsyncWrite + 'static {
    type Item = LibvirtFrame<LibvirtMessage>;
    type Error = ::std::io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        use tokio_io::codec::Decoder;
        use futures::Async;
        let mut codec = LibvirtCodec;
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
        })
    }
}

impl<T> Sink for LibvirtTransport<T> where T: AsyncRead + AsyncWrite + 'static {
    type SinkItem = LibvirtFrame<LibvirtMessage>;
    type SinkError = ::std::io::Error;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        use tokio_io::codec::Encoder;
        use futures::AsyncSink;
        let mut codec = LibvirtCodec;
        let mut buf = BytesMut::with_capacity(64);
        try!(codec.encode(item, &mut buf));
        assert!(try!(self.inner.start_send(buf)).is_ready());
        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.inner.poll_complete()
    }

    fn close(&mut self) -> Poll<(), io::Error> {
        try_ready!(self.poll_complete());
        self.inner.close()
    }
}

pub struct Client {
    inner: multiplex::ClientService<::tokio_uds::UnixStream, LibvirtProto>,
}

impl Client {
    pub fn connect<P: AsRef<Path>>(path: P, handle: &::tokio_core::reactor::Handle) -> Box<Future<Item = Client, Error = ::std::io::Error>> {
        use ::tokio_uds_proto::UnixClient;
        let ret = UnixClient::new(LibvirtProto)
                    .connect(path, handle)
                    .map(|inner| Client { inner });
        future::result(ret).boxed()
    }
}

impl Service for Client {
    type Request = LibvirtMessage;
    type Response = LibvirtMessage;
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
    core.run(
        Client::connect("/var/run/libvirt/libvirt-sock", &handle)
            .and_then(|c| c.call(LibvirtMessage::AuthListRequest))
    ).unwrap();
}