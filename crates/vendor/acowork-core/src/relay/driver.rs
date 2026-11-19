//! Shared single-task yamux driver (design doc 24 §5.2).
//!
//! yamux 0.14 requires ALL connection progress (`poll_next_inbound` /
//! `poll_new_outbound`) to happen from one task. Both sides of a relay
//! tunnel need exactly that loop, so it lives here once:
//!
//! - **relay server** ([`spawn_driver`] with `Mode::Server`): receives
//!   the Gateway-opened control stream as the first inbound, and opens
//!   tagged data streams toward the Gateway when clients connect.
//! - **Gateway client** (`Mode::Client`): opens the control stream, and
//!   receives relay-opened data streams (dispatched by tag byte).
//!
//! Streams are `futures::io` types and are safe to use from any task
//! once obtained — only the connection polling must stay single-tasked.

use std::collections::VecDeque;
use std::task::Poll;
use std::time::Duration;

use futures_util::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{mpsc, oneshot};

/// Request to open one outbound stream through the driver.
struct OpenRequest {
    /// Optional single byte the driver writes to the stream before
    /// handing it over — the opener-side stream tag (§5.2). Writing it
    /// in the driver guarantees the tag precedes any payload bytes the
    /// caller later writes.
    first_byte: Option<u8>,
    resp: oneshot::Sender<anyhow::Result<yamux::Stream>>,
}

/// Handle for opening streams through a running [`spawn_driver`] task.
///
/// Cheap to clone; the handle stays usable until the driver task ends
/// (connection closed or aborted), after which [`open_stream`] fails.
#[derive(Clone)]
pub struct YamuxDriverHandle {
    open_tx: mpsc::Sender<OpenRequest>,
}

impl YamuxDriverHandle {
    /// Open one outbound yamux stream. When `first_byte` is given it is
    /// written to the stream before it is handed back.
    pub async fn open_stream(&self, first_byte: Option<u8>) -> anyhow::Result<yamux::Stream> {
        let (tx, rx) = oneshot::channel();
        self.open_tx
            .send(OpenRequest {
                first_byte,
                resp: tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("tunnel driver gone"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("tunnel driver dropped the open request"))?
    }
}

/// Spawn the single task that owns the yamux [`yamux::Connection`].
///
/// Returns the open-stream handle, the receiver for streams the REMOTE
/// side opened, and the driver task handle. The driver ends when the
/// connection closes or errors, when the inbound receiver is dropped,
/// or when the task is aborted (the intended teardown path for tunnel
/// supervisors — aborting drops the socket, which closes the tunnel).
pub fn spawn_driver<T>(
    socket: T,
    config: yamux::Config,
    mode: yamux::Mode,
    inbound_capacity: usize,
) -> (
    YamuxDriverHandle,
    mpsc::Receiver<yamux::Stream>,
    tokio::task::JoinHandle<()>,
)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let conn = yamux::Connection::new(socket, config, mode);
    let (open_tx, open_rx) = mpsc::channel::<OpenRequest>(64);
    let (inbound_tx, inbound_rx) = mpsc::channel::<yamux::Stream>(inbound_capacity);
    let task = tokio::spawn(drive(conn, open_rx, inbound_tx));
    (YamuxDriverHandle { open_tx }, inbound_rx, task)
}

async fn drive<T>(
    mut conn: yamux::Connection<T>,
    mut open_rx: mpsc::Receiver<OpenRequest>,
    inbound_tx: mpsc::Sender<yamux::Stream>,
) where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut pending_opens: VecDeque<OpenRequest> = VecDeque::new();
    loop {
        let event = futures_util::future::poll_fn(|cx| {
            // 1. Drain new open requests.
            while let Poll::Ready(Some(req)) = open_rx.poll_recv(cx) {
                pending_opens.push_back(req);
            }
            // 2. Satisfy as many open requests as yamux allows right
            //    now. Tagged opens are fulfilled by a short task that
            //    writes the tag byte FIRST, so it always precedes any
            //    payload the caller writes afterwards.
            while !pending_opens.is_empty() {
                match conn.poll_new_outbound(cx) {
                    Poll::Ready(Ok(stream)) => {
                        if let Some(req) = pending_opens.pop_front() {
                            tokio::spawn(async move {
                                let mut stream = stream;
                                if let Some(tag) = req.first_byte {
                                    if let Err(e) = stream.write_all(&[tag]).await {
                                        let _ = req
                                            .resp
                                            .send(Err(anyhow::anyhow!("writing stream tag: {e}")));
                                        return;
                                    }
                                    if let Err(e) = stream.flush().await {
                                        let _ = req
                                            .resp
                                            .send(Err(anyhow::anyhow!("flushing stream tag: {e}")));
                                        return;
                                    }
                                }
                                let _ = req.resp.send(Ok(stream));
                            });
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        if let Some(req) = pending_opens.pop_front() {
                            let _ = req.resp.send(Err(anyhow::anyhow!("yamux open: {e}")));
                        }
                    }
                    Poll::Pending => break,
                }
            }
            // 3. Drive the connection itself.
            conn.poll_next_inbound(cx)
        });

        match event.await {
            Some(Ok(stream)) => {
                if inbound_tx.send(stream).await.is_err() {
                    // Consumer gone — nothing left to do.
                    return;
                }
            }
            Some(Err(e)) => {
                tracing::debug!(error = %e, "yamux connection error; driver ending");
                return;
            }
            None => {
                tracing::debug!("yamux connection closed; driver ending");
                return;
            }
        }
    }
}

/// Bytes moved by [`copy_bidirectional`], per direction.
///
/// Logged on every pipe teardown: "opened, then ended after 60 s having
/// moved 0 bytes in" and "ended after 60 s having moved 4 KiB in / 0 out"
/// are different failures (stream never delivered vs. response never came
/// back) and were indistinguishable when the pipe reported nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct CopyStats {
    /// Bytes read from `a` and written to `b`.
    pub a_to_b: u64,
    /// Bytes read from `b` and written to `a`.
    pub b_to_a: u64,
}

/// futures-io flavored bidirectional copy: pump bytes both ways until one
/// side reaches EOF, errors, or the pipe goes quiet for `idle`. (futures-util
/// does not ship one for `AsyncRead + AsyncWrite` pairs.)
///
/// Shared by the relay's device-domain byte pipe and the Gateway
/// relay-client's stream → local-listener forwarding, so both ends of a
/// tunnel enforce the same inactivity ceiling.
///
/// The `idle` branch exists because a wedged tunnel stream is otherwise
/// invisible: the device keeps writing into a socket nobody is draining,
/// every request queues behind it, and nothing anywhere reports an error —
/// the UI just spins. Timing the pipe out closes BOTH ends, so the device
/// sees a FIN and opens a fresh connection instead of queueing forever.
pub async fn copy_bidirectional<A, B>(a: &mut A, b: &mut B, idle: Duration) -> std::io::Result<CopyStats>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    use futures_util::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut buf_a = [0u8; 16 * 1024];
    let mut buf_b = [0u8; 16 * 1024];
    let mut stats = CopyStats::default();
    let mut a_open = true;
    let mut b_open = true;
    let timer = tokio::time::sleep(idle);
    tokio::pin!(timer);
    loop {
        if !a_open && !b_open {
            break;
        }
        tokio::select! {
            _ = &mut timer => {
                tracing::debug!(
                    a_to_b = stats.a_to_b,
                    b_to_a = stats.b_to_a,
                    "byte pipe idle; closing both ends"
                );
                break;
            }
            read = a.read(&mut buf_a), if a_open => match read {
                // Forward the EOF, do NOT tear the pipe down: `b`'s peer must
                // see that `a` stopped sending, while the bytes still coming
                // back on `b` (the response to a half-closing request) have to
                // keep flowing to `a`. Closing both ends here — the previous
                // behaviour — dropped that response and made the relay's own
                // e2e test wait out every timeout.
                Ok(0) => {
                    a_open = false;
                    let _ = b.close().await;
                }
                Ok(n) => {
                    b.write_all(&buf_a[..n]).await?;
                    stats.a_to_b += n as u64;
                }
                Err(e) => return Err(e),
            },
            read = b.read(&mut buf_b), if b_open => match read {
                Ok(0) => {
                    b_open = false;
                    let _ = a.close().await;
                }
                Ok(n) => {
                    a.write_all(&buf_b[..n]).await?;
                    stats.b_to_a += n as u64;
                }
                Err(e) => return Err(e),
            },
        }
        timer.as_mut().reset(tokio::time::Instant::now() + idle);
    }
    // Always close both ends: a half-closed pipe is exactly the state that
    // lets a client keep writing into a socket nobody is reading.
    let _ = a.close().await;
    let _ = b.close().await;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::io::AsyncReadExt as _;
    use tokio_util::compat::TokioAsyncReadCompatExt as _;

    /// A futures-io duplex pair (tokio duplex + compat).
    fn duplex_pair() -> (
        tokio_util::compat::Compat<tokio::io::DuplexStream>,
        tokio_util::compat::Compat<tokio::io::DuplexStream>,
    ) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        (a.compat(), b.compat())
    }

    /// Client and server connections over an in-memory duplex pair, each
    /// driven by `spawn_driver`. Open a stream on one side, echo on the
    /// other, verify bytes and the tag-first ordering.
    #[tokio::test]
    async fn driver_roundtrip_both_directions() {
        let (client_io, server_io) = duplex_pair();
        let (client, mut client_inbound, _client_task) = spawn_driver(
            client_io,
            yamux::Config::default(),
            yamux::Mode::Client,
            16,
        );
        let (server, mut server_inbound, _server_task) = spawn_driver(
            server_io,
            yamux::Config::default(),
            yamux::Mode::Server,
            16,
        );

        // Client opens a stream with a tag byte; server receives it.
        let mut opened = client.open_stream(Some(0x01)).await.unwrap();
        opened.write_all(b"payload").await.unwrap();

        let mut inbound = server_inbound.recv().await.expect("inbound stream");
        let mut tag = [0u8; 1];
        inbound.read_exact(&mut tag).await.unwrap();
        assert_eq!(tag[0], 0x01, "tag byte must arrive first");

        let mut buf = [0u8; 7];
        inbound.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"payload");

        // Reverse direction: server opens toward the client.
        let mut back = server.open_stream(None).await.unwrap();
        back.write_all(b"reply").await.unwrap();
        let mut inbound = client_inbound.recv().await.expect("inbound stream");
        let mut buf = [0u8; 5];
        inbound.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"reply");
    }

    /// A silent peer must not hold a byte pipe open forever: the copy
    /// returns once the idle ceiling passes with nothing moved. This is the
    /// wedge fix (a device writing into a stream nobody drains used to sit
    /// on the tunnel until the process restarted).
    #[tokio::test]
    async fn idle_pipe_times_out() {
        let (mut a, mut b) = duplex_pair();
        let idle = Duration::from_millis(60);
        let started = tokio::time::Instant::now();
        let stats = copy_bidirectional(&mut a, &mut b, idle).await.unwrap();
        assert_eq!(stats.a_to_b, 0);
        assert_eq!(stats.b_to_a, 0);
        assert!(
            started.elapsed() >= idle,
            "pipe ended after {:?}, before the {idle:?} ceiling",
            started.elapsed()
        );
        drop(b);
    }

    /// The ceiling RESETS on traffic: a trickle slower than `idle` per byte
    /// (an MQTT session pinging every few seconds) must survive many times
    /// the ceiling. Guards against an idle timer that only starts and never
    /// restarts, which would kill healthy long-lived pipes.
    #[tokio::test]
    async fn trickle_keeps_the_pipe_alive() {
        // Two pairs so the test drives the outer ends while the copy owns the
        // inner ones. If the ceiling fired early the copy would return, drop
        // its ends, and the next write/read below would fail.
        let (mut x1, x2) = duplex_pair();
        let (mut y1, y2) = duplex_pair();
        let idle = Duration::from_millis(80);
        let task =
            tokio::spawn(async move { copy_bidirectional(&mut { x2 }, &mut { y2 }, idle).await });
        let mut buf = [0u8; 1];
        for i in 0..12u8 {
            tokio::time::sleep(Duration::from_millis(25)).await;
            x1.write_all(&[i]).await.unwrap();
            y1.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf[0], i, "byte {i} did not reach the far end");
        }
        drop(x1);
        drop(y1);
        let stats = task.await.unwrap().unwrap();
        assert_eq!(stats.a_to_b, 12);
    }

    /// An EOF on one side is forwarded as a half-close, not a teardown: the
    /// bytes still arriving on the other side must reach the peer. A client
    /// that finishes its request with a FIN and waits for the response is the
    /// normal HTTP shape here — closing BOTH ends on the first EOF (the
    /// previous behaviour) dropped that response, and the relay's own e2e
    /// test only finished then because the idle ceiling happened to fire.
    #[tokio::test]
    async fn half_close_forwards_eof_but_keeps_pumping() {
        // Outer ends are driven by the test, inner ones by the copy.
        let (mut x1, x2) = duplex_pair();
        let (mut y1, y2) = duplex_pair();
        let idle = Duration::from_millis(500);
        let task =
            tokio::spawn(async move { copy_bidirectional(&mut { x2 }, &mut { y2 }, idle).await });

        let request = b"GET / HTTP/1.1\r\n\r\n";
        x1.write_all(request).await.unwrap();
        x1.close().await.unwrap(); // request complete; x1 still readable

        let mut got = [0u8; 18];
        y1.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, request);

        y1.write_all(b"reply").await.unwrap();
        let mut out = [0u8; 5];
        x1.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"reply", "response must survive the request EOF");

        drop(y1);
        let stats = task.await.unwrap().unwrap();
        assert_eq!(stats.a_to_b, request.len() as u64);
        assert_eq!(stats.b_to_a, 5);
    }

    /// Aborting the driver task closes the tunnel: open_stream fails
    /// afterwards and the peer observes the connection ending.
    #[tokio::test]
    async fn abort_closes_the_tunnel() {
        let (client_io, server_io) = duplex_pair();
        let (client, _client_inbound, client_task) = spawn_driver(
            client_io,
            yamux::Config::default(),
            yamux::Mode::Client,
            4,
        );
        let (_server, mut server_inbound, server_task) = spawn_driver(
            server_io,
            yamux::Config::default(),
            yamux::Mode::Server,
            4,
        );

        let mut stream = client.open_stream(None).await.unwrap();
        stream.write_all(b"hi").await.unwrap();
        let mut inbound = server_inbound.recv().await.expect("inbound arrives");

        client_task.abort();
        let _ = client_task.await;

        // The peer's stream dies (EOF or reset) — never hangs.
        let mut buf = [0u8; 8];
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), inbound.read(&mut buf))
            .await
            .expect("read completes after peer abort");
        let _ = server_task.await;
    }
}
