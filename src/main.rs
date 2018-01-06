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

use std::collections::VecDeque;
use std::net::{SocketAddr, IpAddr};

use futures::{Poll, Future, Stream, Async};

use h2::RecvStream;

use http::*;

use openssl::ssl::{SslMethod, SslConnectorBuilder};

use tokio_core::net::{TcpStream, TcpStreamNew};
use tokio_core::reactor::{Core, Handle};

use tokio_openssl::SslConnectorExt;

use trust_dns_resolver::ResolverFuture;
use trust_dns_resolver::config::*;
use trust_dns_resolver::lookup_ip::{LookupIp, LookupIpFuture};

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
    let query =
        // Start by resolving the domain to query
        resolve("nghttp2.org.", &handle)
        // Convert errors to common type
        .map_err(|err| Error::Dns(format!("{}", err)))
        // Now try establishing a TCP connection to each resolved address
        .and_then(|ips| ConnectLoop::new(ips, 443, &handle).map_err(Error::Tcp))
        // Add TLS to the TCP stream
        .and_then(|stream| {
            // TODO how to handle these "immediate" errors?
            let mut builder = SslConnectorBuilder::new(SslMethod::tls()).unwrap();
            builder.set_alpn_protocols(&[b"h2"]).unwrap();
            builder
                .build()
                // The domain name is important here for SNI
                .connect_async("nghttp2.org", stream)
                .map_err(Error::Ssl)
        })
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

/// An error resulting from establishing a TCP connection from a list of IpAddr.
#[derive(Debug, Fail)]
#[fail(display = "Failed to establish TCP connection")]
struct TcpConnectError;

/// Unified error type for the demo
///
/// The details here aren't important, just that we have a unified error type
/// for the future chain in `main()`.
#[derive(Debug, Fail)]
enum Error {
    #[fail(display = "dns error: {}", _0)]
    Dns(String),
    #[fail(display = "{}", _0)]
    Tcp(#[cause] TcpConnectError),
    #[fail(display = "{}", _0)]
    Ssl(#[cause] ::openssl::ssl::Error),
    #[fail(display = "{}", _0)]
    H2(#[cause] ::h2::Error),
}

/// Future combinator for establishing a `TcpStream` from a set of `IpAddr`.
///
/// This can be thought of as a `connect()` loop over `addrinfo`, except that
/// it's asynchronous and driven by the event loop.
struct ConnectLoop {
    ips: VecDeque<IpAddr>,
    port: u16,
    cur: TcpStreamNew,
    handle: Handle,
}

impl ConnectLoop {
    /// Create the ConnectLoop combinator
    ///
    /// The `ips` parameter is the result of resolving a domain with
    /// trust-dns-resolver. The port is needed since a TCP connection is both an
    /// address and port.
    ///
    /// The `handle` argument is something of a curiosity when unfamiliar with
    /// how Futures interact with tokio-core and a mio EventLoop. The exact
    /// details of this are the subject of a much longer document, but here is
    /// the gist.
    ///
    /// When calling TcpStream::connect, an asynchronous connection process is
    /// started. A socket is created, set to non-blocking mode, and connection
    /// process initiated. However, it's not usable yet, and we get a `Future`
    /// for a `TcpStream`. When `poll` is called on this future to see if it's
    /// ready (for instance, as a side effect of calling and_then on the
    /// `Future<TcpStream>`), the `Handle` is needed to register interest on the
    /// underlying mio event loop. `poll()` then returns `Async::NotReady` which
    /// causes the rest of the state machine to return NotReady, and ultimately,
    /// the task is suspended until the event loop gets an event for this file
    /// descriptor.
    fn new(ips: LookupIp, port: u16, handle: &Handle) -> Self {
        let mut ips = ips.iter().collect::<VecDeque<IpAddr>>();
        let ip = ips.pop_front().expect("at least one record");
        Self {
            ips,
            handle: handle.to_owned(),
            port,
            cur: TcpStream::connect(&SocketAddr::new(ip, port), handle),
        }
    }
}

impl Future for ConnectLoop {
    type Item = TcpStream;
    type Error = TcpConnectError;

    // Each call to poll advances the connect loop
    //
    // On poll(), check if the current Future<TcpStream> is ready. If it errors
    // out, move onto the next address and poll() it. If none of the addresses
    // are connectable, resolve the future with an Err(TcpConnectError).
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            return match self.cur.poll() {
                // Try next address on error
                Err(_err) => {
                    match self.ips.pop_front() {
                        // Got another candidate, try and connect
                        Some(ip) => {
                            self.cur = TcpStream::connect(
                                &SocketAddr::new(ip, self.port),
                                &self.handle
                            );
                            continue;
                        }
                        // Ran out of addresses
                        None => Err(TcpConnectError),
                    }
                },
                // Otherwise return current state
                Ok(Async::Ready(sock)) => Ok(Async::Ready(sock)),
                Ok(Async::NotReady) => Ok(Async::NotReady),
            }
        }
    }
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

/// Resolve the provided domain
///
/// Returns a Future<LookupIp>. For details about the `Handle` argument, see the
/// doc comment on `ConnectLoop::new()`
fn resolve(domain: &str, handle: &Handle) -> LookupIpFuture {
    let resolver = ResolverFuture::new(
        ResolverConfig::default(),
        ResolverOpts::default(),
        handle
    );

    resolver.lookup_ip(domain)
}

