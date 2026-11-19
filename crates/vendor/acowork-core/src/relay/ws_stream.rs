//! WebSocket ↔ byte-stream adapter (design doc 24 §5.2).
//!
//! yamux multiplexes over a full-duplex byte stream
//! (`futures::io::AsyncRead + AsyncWrite`), but the tunnel's transport is a
//! WebSocket — a message channel. This module bridges the two: binary WS
//! payloads become stream bytes and vice versa.
//!
//! The halves are modelled as two independent poll-based traits so a single
//! connection can be read and written concurrently (yamux needs that) and so
//! both tungstenite (Gateway tunnel client) and axum (relay `/tunnel`
//! endpoint) WebSocket types can adapt with no shared dependency between
//! them.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::io::{AsyncRead, AsyncWrite};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::WebSocketStream;

/// The readable half of a binary WebSocket channel.
///
/// `Ok(None)` means the peer closed the connection. Ping/pong frames are
/// consumed transparently (tungstenite queues the pong reply itself).
pub trait WsReader: Send + Unpin {
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Vec<u8>>>>;
}

/// The writable half of a binary WebSocket channel.
pub trait WsWriter: Send + Unpin {
    fn poll_send(&mut self, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<()>>;
}

/// A WebSocket adapted into the byte stream yamux requires.
pub struct WsByteStream {
    reader: Box<dyn WsReader>,
    writer: Box<dyn WsWriter>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl WsByteStream {
    /// Assemble from the two channel halves.
    pub fn new(reader: Box<dyn WsReader>, writer: Box<dyn WsWriter>) -> Self {
        Self {
            reader,
            writer,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }

    /// Wrap a tokio-tungstenite `WebSocketStream` (Gateway tunnel client).
    pub fn tungstenite<S>(ws: WebSocketStream<S>) -> Self
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (sink, stream) = ws.split();
        Self::new(
            Box::new(TungsteniteReader { stream }),
            Box::new(TungsteniteWriter::new(sink)),
        )
    }
}

impl AsyncRead for WsByteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            // Serve (and clear) any buffered payload first.
            if self.read_pos < self.read_buf.len() {
                let remaining = &self.read_buf[self.read_pos..];
                let n = remaining.len().min(buf.len());
                buf[..n].copy_from_slice(&remaining[..n]);
                self.read_pos += n;
                if self.read_pos == self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_pos = 0;
                }
                return Poll::Ready(Ok(n));
            }

            // Buffer empty — poll the next binary message.
            match self.reader.poll_recv(cx) {
                Poll::Ready(Ok(Some(data))) => {
                    if data.is_empty() {
                        // A zero-length message reads as EOF below; skip it
                        // and keep polling instead.
                        continue;
                    }
                    self.read_buf = data;
                    self.read_pos = 0;
                }
                Poll::Ready(Ok(None)) => return Poll::Ready(Ok(0)), // EOF
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for WsByteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.writer.poll_send(cx, buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Every poll_send flushes the sink; nothing extra to do.
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Dropping the halves closes the WS connection; yamux FIN semantics
        // are carried in yamux's own framing.
        Poll::Ready(Ok(()))
    }
}

fn ws_io_err(e: tokio_tungstenite::tungstenite::Error) -> io::Error {
    io::Error::other(e.to_string())
}

/// Tungstenite reader half.
pub struct TungsteniteReader<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    stream: SplitStream<WebSocketStream<S>>,
}

impl<S> WsReader for TungsteniteReader<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Vec<u8>>>> {
        loop {
            match self.stream.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(None)),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(ws_io_err(e))),
                Poll::Ready(Some(Ok(msg))) => match msg {
                    WsMessage::Binary(data) => return Poll::Ready(Ok(Some(data.to_vec()))),
                    // Text frames are a protocol violation on this channel.
                    WsMessage::Text(t) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unexpected text WS frame: {t}"),
                        )))
                    }
                    // Pongs arrive unsolicited; pings are auto-answered by
                    // tungstenite on the next write/flush — both are noise
                    // to the byte-stream view.
                    WsMessage::Ping(_) | WsMessage::Pong(_) => continue,
                    WsMessage::Close(_) | WsMessage::Frame(_) => {
                        return Poll::Ready(Ok(None))
                    }
                },
            }
        }
    }
}

/// Tungstenite writer half.
///
/// `poll_send` must be a state machine around the Sink contract: a
/// message is passed to `start_send` exactly ONCE per logical send. A
/// naive ready→start_send→flush on every poll DUPLICATES the message
/// whenever the first flush returns `Pending` (the caller re-polls
/// `poll_write`, and `start_send` runs again with the same buffer) —
/// under socket backpressure that silently corrupts the stream. The
/// `in_flight` flag keeps the re-poll path in flush-only mode until the
/// accepted message is fully on the wire.
pub struct TungsteniteWriter<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    sink: SplitSink<WebSocketStream<S>, WsMessage>,
    /// A message was accepted via `start_send` but its flush has not
    /// completed yet — subsequent polls must only flush, never enqueue.
    in_flight: bool,
}

impl<S> TungsteniteWriter<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    fn new(sink: SplitSink<WebSocketStream<S>, WsMessage>) -> Self {
        Self {
            sink,
            in_flight: false,
        }
    }
}

impl<S> WsWriter for TungsteniteWriter<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    fn poll_send(&mut self, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<()>> {
        // Re-poll of an in-flight send: flush only (the message is
        // already queued — enqueueing it again would duplicate it).
        if self.in_flight {
            return match self.sink.poll_flush_unpin(cx) {
                Poll::Ready(Ok(())) => {
                    self.in_flight = false;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => {
                    self.in_flight = false;
                    Poll::Ready(Err(ws_io_err(e)))
                }
                Poll::Pending => Poll::Pending,
            };
        }
        // Fresh send: ready → start_send → flush. If the flush cannot
        // complete within this poll, mark in-flight and let re-polls
        // take the flush-only path above.
        if let Err(e) = std::task::ready!(self.sink.poll_ready_unpin(cx)) {
            return Poll::Ready(Err(ws_io_err(e)));
        }
        if let Err(e) = self
            .sink
            .start_send_unpin(WsMessage::Binary(data.to_vec().into()))
        {
            return Poll::Ready(Err(ws_io_err(e)));
        }
        match self.sink.poll_flush_unpin(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(ws_io_err(e))),
            Poll::Pending => {
                self.in_flight = true;
                Poll::Pending
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// A raw in-memory duplex pipe speaking WS framing on both ends.
    ///
    /// NOTE: `client_async` awaits the server's 101 response before
    /// returning, so the client and server halves MUST be driven
    /// concurrently (sequential awaits deadlock: the client waits for a
    /// response only `accept_async` can send).
    async fn ws_pair() -> (WsByteStream, WsByteStream) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (client_ws, server_ws) = tokio::join!(
            tokio_tungstenite::client_async("ws://localhost/tunnel", client_io),
            tokio_tungstenite::accept_async(server_io)
        );
        let client_ws = client_ws.unwrap().0;
        let server_ws = server_ws.unwrap();
        (
            WsByteStream::tungstenite(client_ws),
            WsByteStream::tungstenite(server_ws),
        )
    }

    #[tokio::test]
    async fn bytes_roundtrip_both_directions() {
        let (mut a, mut b) = ws_pair().await;

        a.write_all(b"hello relay").await.unwrap();
        let mut buf = [0u8; 11];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello relay");

        b.write_all(b"hello gateway").await.unwrap();
        let mut buf = [0u8; 13];
        a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello gateway");
    }

    #[tokio::test]
    async fn large_payload_survives() {
        // Byte-stream semantics: a large payload may coalesce or split
        // across messages, but all bytes must arrive intact and in order.
        //
        // The reader MUST run concurrently with the writer: the payload
        // (100 KB) is sent as a single WS message and the in-memory
        // duplex pipe only buffers 64 KB, so a sequential
        // write-then-read deadlocks on socket backpressure (the writer
        // waits for the reader to drain while the "test" waits for the
        // writer to finish).
        let (mut a, mut b) = ws_pair().await;
        let big: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();

        let expected_len = big.len();
        let reader = tokio::spawn(async move {
            let mut received = Vec::with_capacity(expected_len);
            let mut chunk = [0u8; 4096];
            while received.len() < expected_len {
                let n = b.read(&mut chunk).await.unwrap();
                assert!(n > 0, "unexpected EOF mid-payload");
                received.extend_from_slice(&chunk[..n]);
            }
            received
        });

        a.write_all(&big).await.unwrap();
        let received = reader.await.unwrap();
        assert_eq!(received, big);
    }

    #[tokio::test]
    async fn drop_closes_and_reads_eof() {
        let (mut a, b) = ws_pair().await;
        drop(b);
        // The reader observes EOF (or an orderly close error) — never a hang.
        let mut buf = [0u8; 8];
        loop {
            match a.read(&mut buf).await {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    }
}
