use std::time::Duration;
use std::io;
use std::net::{SocketAddr, IpAddr};
use std::collections::VecDeque;

use trust_dns_resolver::ResolverFuture;
use trust_dns_resolver::config::*;
use trust_dns_resolver::lookup_ip::{LookupIp};

use tokio_core::reactor::Handle;
use tokio_core::net::{TcpStream, TcpStreamNew};
use tokio_core::reactor::Timeout;

use futures::future::{self, Future, Either};
use futures::{Async, Poll, done};

/// Error from establishing a connection.
#[derive(Debug, Fail)]
pub enum Error {
    /// Connecting took too long and the timeout was fired
    #[fail(display = "Timeout out while establishing connection")]
    Timeout,

    /// An I/O error occurred while managing a Timeout
    #[fail(display = "I/O Error while managing the timeout: {}", _0)]
    Timer(#[cause] io::Error),

    /// An I/O error occurred while establishing the connection
    ///
    /// If returned from the ConnectLoop future, this is the final I/O error
    /// received; errors while connecting to earlier candidates are ignored.
    #[fail(display = "I/O Error while connecting: {}", _0)]
    Connect(#[cause] io::Error),

    /// Failed to resolve the hostname
    #[fail(display = "Failed resolving hostname: {}", _0)]
    Dns(String)
}


/// Resolve the provided hostname
///
/// Returns a Future<LookupIp>. For details about the `Handle` argument, see the
/// doc comment on `ConnectLoop::new()`
fn resolve(domain: &str, handle: &Handle) -> Box<Future<Item=LookupIp, Error=Error>> {
    let resolver = ResolverFuture::new(
        ResolverConfig::default(),
        ResolverOpts::default(),
        handle
    );

    Box::new(resolver
        .lookup_ip(domain)
        .map_err(|e| Error::Dns(e.to_string()))
    )
}

/// Resolve `domain`, connect on `port`, and do so within `timeout`
///
/// Handles DNS resolution and TCP connection setup. If a timeout occurs, the
/// returned `Future` will resolve with a `net::Error::Timeout`.
pub fn connect(
    domain: &str,
    port: u16,
    timeout: Duration,
    handle: &Handle
) -> Box<Future<Item=TcpStream, Error=Error>> {
    // A couple of handle clones to deal with ownership
    let handle1 = handle.clone();
    let handle2 = handle.clone();

    // Returning a Box so we don't need to name this horrible type.
    Box::new(
        // DNS resolution
        resolve(domain, handle)
        // net::Error
        .map_err(|e| Error::Dns(e.to_string()))
        // Create a timeout
        .and_then(move |ips| {
            done(match Timeout::new(timeout, &handle1) {
                Ok(timeout) => Ok((ips, timeout)),
                Err(err) => Err(Error::Timer(err))
            })
        })
        // Start the connect loop and run it against timeout
        .and_then(move |(ips, timeout)| {
            ConnectLoop::new(ips, port, &handle2).map_err(Error::Connect)
                .select2(timeout.map_err(Error::Timer))
                .map_err(|err| err.split().0)
        })
        // Either return the TCP stream or return an Error::Timeout
        .and_then(|tcp_or_timeout| {
            match tcp_or_timeout {
                Either::A((stream, _)) => Either::A(future::ok(stream)),
                Either::B((_, _)) => Either::B(future::err(Error::Timeout))
            }
        }))
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
    pub fn new(ips: LookupIp, port: u16, handle: &Handle) -> Self {
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
    type Error = io::Error;

    // Each call to poll advances the connect loop
    //
    // On poll(), check if the current Future<TcpStream> is ready. If it errors
    // out, move onto the next address and poll() it. If none of the addresses
    // are connectable, resolve the future with an Err(TcpConnectError).
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            return match self.cur.poll() {
                // Try next address on error
                Err(err) => {
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
                        None => Err(err),
                    }
                },
                // Otherwise return current state
                Ok(Async::Ready(sock)) => Ok(Async::Ready(sock)),
                Ok(Async::NotReady) => Ok(Async::NotReady),
            }
        }
    }
}
