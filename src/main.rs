//! Demo program fetching a resource over HTTP/2
//!
//! The demo is completely asynchronous. DNS resolution is done with
//! [trust-dns-resolver], Establishing a TCP connection is done with
//! [tokio-core]'s TcpStream, TLS with ALPN is provided via the [tokio-openssl]
//! crate, and HTTP/2 protocol via the [h2] crate.
//!
//! [tokio-core]: https://docs.rs/tokio-core/
//! [h2]: https://carllerche.github.io/h2/h2/index.html
//! [trust-dns-resolver]: https://docs.rs/trust-dns-resolver/
//! [tokio-openssl]: https://docs.rs/tokio-openssl/
extern crate h2;
extern crate openssl;
extern crate tokio_openssl;
extern crate trust_dns_resolver;
extern crate tokio_core;
#[macro_use] extern crate futures;
extern crate http;
#[macro_use] extern crate failure;

use std::time::Duration;

use futures::{Poll, Future, Stream, Async};
use futures::future::{Either, FutureResult};

use h2::RecvStream;

use http::*;

use openssl::ssl::{self, SslMethod, SslConnectorBuilder};

use tokio_core::net::{TcpStream};
use tokio_core::reactor::{Core};

use tokio_openssl::{SslConnectorExt, SslStream, ConnectAsync};

mod net;

/// The program in its entirety.
///
/// Normally this would be after all of the supporting code. I've placed it at
/// the top as it should be read first in this learning exercise.
fn main() {
    // Create the event loop.
    let mut io_loop = Core::new().unwrap();

    // And a handle for evented types to be added.
    let handle = io_loop.handle();

    // Build the query. This effectively has the type `impl Future<String>`.
    let query = net::connect("nghttp2.org.", 443, Duration::from_secs(10), &handle)
        .map_err(Error::Tcp)
        // Add TLS to the TCP stream
        .and_then(|stream| tls(stream, "nghttp2.org").map_err(Error::Ssl))
        // Establish h2 on the ssl stream
        .and_then(|ssl_stream| {
            ::h2::client::handshake(ssl_stream)
                .map_err(Error::H2)
        })
        // And finally, send the HTTP request
        .and_then(|(mut client, connection)| {
            // Build the http::Request
            let request = Request::builder()
                .uri("https://nghttp2.org/httpbin/get")
                .header("User-Agent", "h2-demo/0.1")
                .body(())
                .unwrap();

            let (response_future, _stream) = client.send_request(request, true).unwrap();

            // Spawn a task to run the connection
            //
            // If receiving connection errors is important, they should be
            // sent back to the controlling task instead of simply printing.
            handle.spawn(connection.map_err(|e| eprintln!("conn error: {}", e)));

            response_future
                // When the response arrives..
                .and_then(|res /* http::response::Response */| {
                    // Prints the Debug information for this response -- status,
                    // HTTP version, and headers. The body is a future::Stream
                    // of bytes.
                    println!("Response: {:?}", res);

                    // Grab the ReceiveStream
                    let (_parts, recv_stream) = res.into_parts();

                    // Return a combinator which will buffer the response into a
                    // String.
                    BufferResponse::new(recv_stream)
                })
                // Or if there's an error, convert to the unified error type
                .map_err(Error::H2)
        });

    // Run the query to completion
    let response = io_loop.run(query).unwrap();

    // And print the result
    println!("{}", String::from_utf8(response).unwrap());
}

/// Helper when returning an `Either` future where the B variant is an immediate Error.
macro_rules! either_try {
    ($res:expr) => {
        match $res {
            Ok(v) => v,
            Err(e) => return ::futures::future::Either::B(
                ::futures::future::err(::std::convert::From::from(e))
            )
        }
    }
}

/// Wrap a TcpStream with TLS
fn tls(stream: TcpStream, host: &str)
    // `impl Future<Item=SslStream<TcpStream>, Error=ssl::Error>`
    -> Either<ConnectAsync<TcpStream>, FutureResult<SslStream<TcpStream>, ssl::Error>>
{
    let mut builder = either_try!(SslConnectorBuilder::new(SslMethod::tls()));
    either_try!(builder.set_alpn_protocols(&[b"h2"]));

    let connect_async = builder
        .build()
        // The domain name is important here for SNI
        .connect_async(host, stream);

    Either::A(connect_async)
}

/// Unified error type for the demo
///
/// The details here aren't important, just that we have a unified error type
/// for the future chain in `main()`.
#[derive(Debug, Fail)]
enum Error {
    #[fail(display = "{}", _0)]
    Tcp(#[cause] net::Error),
    #[fail(display = "{}", _0)]
    Ssl(#[cause] ::openssl::ssl::Error),
    #[fail(display = "{}", _0)]
    H2(#[cause] ::h2::Error),
}

/// A combinator which will buffer a `RecvStream` into a Vec<u8>
///
/// This is used to aggregrate the response body of an h2 stream into a buffer.
struct BufferResponse {
    stream: RecvStream,
    stream_done: bool,
    buf: Vec<u8>
}

impl BufferResponse {
    /// Create the BufferResponse combinator
    pub fn new(stream: RecvStream) -> Self {
         Self {
            stream,
            stream_done: false,
            buf: Vec::new(),
         }
    }
}

impl Future for BufferResponse {
    type Item = Vec<u8>;
    type Error = h2::Error;

    // The poll impl pushes data into the buffer every time more data becomes
    // available.
    //
    // It's also important to receive any trailers that may arrive, but for the
    // purposes of this demo, they are not returned.
    fn poll(&mut self) -> Poll<Self::Item, h2::Error> {
        loop {
            if self.stream_done {
                // Get any trailers (like headers, but afterwards)
                //
                // We don't need them in this example, so they will just get
                // dropped immediately.
                let _ = try_ready!(self.stream.poll_trailers());

                // The response has been completely read. Return the buffer.
                let buf = ::std::mem::replace(&mut self.buf, Vec::new());
                return Ok(Async::Ready(buf));
            } else {
                match try_ready!(self.stream.poll()) {
                    Some(chunk) => self.buf.extend_from_slice(&chunk),
                    None => {
                        self.stream_done = true;
                    },
                }
            }
        }
    }
}


