//! Post-handshake ownership only. Plaintext is admitted in FIFO order; exactly
//! one writer owns encryption/send counters and one reader owns receive counters.
use super::{Encrypt, WsMessage, WsStream, DEFAULT_MAX_MESSAGE_SIZE};
use bytes::{Bytes, BytesMut};
use futures::{Sink, SinkExt, Stream, StreamExt};
use serde_derive::Serialize;
use std::{io, pin::Pin, sync::{Arc, Mutex, Weak, atomic::{AtomicBool, AtomicU64, Ordering}},
    task::{Context, Poll}, time::{Duration, Instant}};
use tokio::{sync::{mpsc, watch, Notify, OwnedSemaphorePermit, Semaphore}, task::JoinHandle};
use tungstenite::Error as WsError;

const CONTROL_PACKETS: usize = 64;
const RECEIVE_PACKETS: usize = 32;
const BYTE_BUDGET: usize = DEFAULT_MAX_MESSAGE_SIZE;
const TERMINAL_BYTES: usize = 64 << 10;

pub struct VideoTiming { pub queued: Duration, pub writing: Duration }
pub struct DesktopDuplexConfig {
    pub video_ready: Arc<Notify>,
    pub video_observer: Option<Arc<dyn Fn(VideoTiming) + Send + Sync>>,
    /// Optional local diagnostic pacing; capped at2s and expires after60s.
    pub diagnostic_video_delay: Duration,
}

#[derive(Clone)]
struct Failure { message: Arc<str>, kind: io::ErrorKind, eof: bool }
impl Failure { fn error(&self) -> io::Error { io::Error::new(self.kind, self.message.to_string()) } }

struct Shared {
    io: Arc<Mutex<WsStream>>, failure: watch::Sender<Option<Failure>>,
    written: watch::Sender<u64>, control_count: Arc<Semaphore>, control_bytes: Arc<Semaphore>,
    video_bytes: Arc<Semaphore>, terminal_bytes: Arc<Semaphore>, receive_bytes: Arc<Semaphore>, video_ready: Arc<Notify>,
    video_inflight: AtomicBool, video_writing: AtomicBool, closing: AtomicBool, admitted: AtomicU64,
    written_packets: AtomicU64, retired_packets: AtomicU64,
    received: AtomicU64, delivered: AtomicU64, key_mode: &'static str, tcp_nodelay: Option<bool>,
    observer: Option<Arc<dyn Fn(VideoTiming) + Send + Sync>>, started: Instant, delay: Duration,
}
impl Shared {
    fn fail(&self, message: impl ToString, kind: io::ErrorKind, eof: bool) {
        let message: Arc<str> = message.to_string().chars().take(512).collect::<String>().into();
        self.failure.send_if_modified(|current| {
            if current.is_some() { return false; }
            *current = Some(Failure { message, kind, eof }); true
        });
        self.video_ready.notify_one();
    }
    fn failure(&self) -> Option<Failure> { self.failure.borrow().clone() }
    fn delay(&self) -> Duration { if self.started.elapsed() < Duration::from_secs(60) { self.delay } else { Duration::ZERO } }
}

/// Locks cover an individual nonblocking poll, never an awaited write. TLS and
/// WebSocket protocol state remain shared, including their ping/pong flushing.
#[derive(Clone)]
struct Io(Arc<Mutex<WsStream>>);
impl Stream for Io {
    type Item = Result<WsMessage, WsError>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.0.lock() {
            Ok(mut io) => Pin::new(&mut *io).poll_next(cx),
            Err(_) => Poll::Ready(Some(Err(WsError::Io(io::Error::new(io::ErrorKind::Other, "WebSocket state unavailable"))))),
        }
    }
}
impl Sink<WsMessage> for Io {
    type Error = WsError;
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.0.lock() { Ok(mut io) => Pin::new(&mut *io).poll_ready(cx), Err(_) => Poll::Ready(Err(poisoned())) }
    }
    fn start_send(self: Pin<&mut Self>, item: WsMessage) -> Result<(), Self::Error> {
        self.0.lock().map_err(|_| poisoned()).and_then(|mut io| Pin::new(&mut *io).start_send(item))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.0.lock() { Ok(mut io) => Pin::new(&mut *io).poll_flush(cx), Err(_) => Poll::Ready(Err(poisoned())) }
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.0.lock() { Ok(mut io) => Pin::new(&mut *io).poll_close(cx), Err(_) => Poll::Ready(Err(poisoned())) }
    }
}
fn poisoned() -> WsError { WsError::Io(io::Error::new(io::ErrorKind::Other, "WebSocket state unavailable")) }

struct VideoCredit(Arc<Shared>);
impl Drop for VideoCredit {
    fn drop(&mut self) {
        self.0.video_writing.store(false, Ordering::Relaxed);
        self.0.video_inflight.store(false, Ordering::Release);
        self.0.video_ready.notify_one();
    }
}
struct Outbound {
    bytes: Bytes, encrypt: bool, terminal: bool, sequence: u64, queued: Instant, timeout: u64,
    _bytes: OwnedSemaphorePermit, _count: Option<OwnedSemaphorePermit>, video: Option<VideoCredit>,
}
struct Inbound { bytes: BytesMut, _bytes: OwnedSemaphorePermit }

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopDuplexStats {
    key_mode: &'static str, tcp_nodelay: Option<bool>, video_inflight: bool, video_writing: bool, closing: bool,
    admitted_packets: u64, written_packets: u64, retired_packets: u64, received_packets: u64, delivered_packets: u64,
    outstanding_control_packets: usize, outstanding_control_bytes: usize,
    outstanding_video_bytes: usize, buffered_receive_bytes: usize,
    max_control_packets: usize, max_receive_packets: usize, byte_budget_per_class: usize,
    diagnostic_video_delay_ms: u64, failure: Option<String>,
}
#[derive(Clone)]
pub struct DesktopDuplexMonitor(Weak<Shared>);
impl DesktopDuplexMonitor {
    pub fn snapshot(&self) -> Option<DesktopDuplexStats> {
        let shared = self.0.upgrade()?;
        Some(DesktopDuplexStats { key_mode:shared.key_mode, tcp_nodelay:shared.tcp_nodelay,
            video_inflight:shared.video_inflight.load(Ordering::Acquire), video_writing:shared.video_writing.load(Ordering::Relaxed),
            closing:shared.closing.load(Ordering::Acquire), admitted_packets:shared.admitted.load(Ordering::Relaxed),
            written_packets:shared.written_packets.load(Ordering::Relaxed), retired_packets:shared.retired_packets.load(Ordering::Relaxed),
            received_packets:shared.received.load(Ordering::Relaxed), delivered_packets:shared.delivered.load(Ordering::Relaxed),
            outstanding_control_packets:CONTROL_PACKETS - shared.control_count.available_permits(),
            outstanding_control_bytes:BYTE_BUDGET - shared.control_bytes.available_permits(),
            outstanding_video_bytes:BYTE_BUDGET - shared.video_bytes.available_permits(),
            buffered_receive_bytes:BYTE_BUDGET - shared.receive_bytes.available_permits(),
            max_control_packets:CONTROL_PACKETS, max_receive_packets:RECEIVE_PACKETS, byte_budget_per_class:BYTE_BUDGET,
            diagnostic_video_delay_ms:shared.delay().as_millis() as u64,
            failure:shared.failure().map(|failure| failure.message.to_string()) })
    }
}

pub(super) struct Duplex {
    shared: Arc<Shared>, tx: mpsc::Sender<Outbound>, rx: mpsc::Receiver<Inbound>,
    failure: watch::Receiver<Option<Failure>>, written: watch::Receiver<u64>, sequence: u64,
    reader: Option<JoinHandle<()>>, writer: Option<JoinHandle<()>>,
}
impl Duplex {
    pub fn new(io: WsStream, encrypt: Option<Encrypt>, config: DesktopDuplexConfig) -> Self {
        let (failure_tx, failure) = watch::channel(None);
        let (written_tx, written) = watch::channel(0);
        // Query the actual TCP socket below TLS. A type-erased proxy transport
        // cannot be inspected here and must remain unknown in diagnostics.
        let tcp_nodelay = match &io {
            super::Either::Left(stream) => stream.get_ref().get_ref().nodelay().ok(),
            super::Either::Right(_) => None,
        };
        let key_mode = encrypt.as_ref().map_or("none", |key| if key.has_separate_receive_key() { "split-v1" } else { "legacy" });
        let shared = Arc::new(Shared { io:Arc::new(Mutex::new(io)), failure:failure_tx, written:written_tx,
            control_count:Arc::new(Semaphore::new(CONTROL_PACKETS)), control_bytes:Arc::new(Semaphore::new(BYTE_BUDGET)),
            video_bytes:Arc::new(Semaphore::new(BYTE_BUDGET)), terminal_bytes:Arc::new(Semaphore::new(TERMINAL_BYTES)), receive_bytes:Arc::new(Semaphore::new(BYTE_BUDGET)),
            video_ready:config.video_ready, video_inflight:AtomicBool::new(false), video_writing:AtomicBool::new(false),
            closing:AtomicBool::new(false), admitted:AtomicU64::new(0), written_packets:AtomicU64::new(0), retired_packets:AtomicU64::new(0), received:AtomicU64::new(0), delivered:AtomicU64::new(0),
            key_mode, tcp_nodelay, observer:config.video_observer, started:Instant::now(), delay:config.diagnostic_video_delay.min(Duration::from_secs(2)) });
        let (tx, outgoing) = mpsc::channel(CONTROL_PACKETS + 2);
        let (incoming, rx) = mpsc::channel(RECEIVE_PACKETS);
        // Clone once at the consuming handoff: the reader exclusively calls dec,
        // the writer exclusively calls enc. No writable cipher owner is exposed.
        let read_cipher = encrypt.clone();
        let reader_shared = shared.clone();
        let reader = tokio::spawn(async move { read(reader_shared, read_cipher, incoming).await; });
        let writer_shared = shared.clone();
        let writer = tokio::spawn(async move { write(writer_shared, encrypt, outgoing).await; });
        Self { shared, tx, rx, failure, written, sequence:0, reader:Some(reader), writer:Some(writer) }
    }
    pub fn monitor(&self) -> DesktopDuplexMonitor { DesktopDuplexMonitor(Arc::downgrade(&self.shared)) }
    pub fn video_ready(&self) -> bool { self.shared.failure().is_none() && !self.shared.closing.load(Ordering::Acquire) && !self.shared.video_inflight.load(Ordering::Acquire) }
    pub fn video_writing(&self) -> bool { self.shared.video_writing.load(Ordering::Relaxed) }
    pub fn secured(&self) -> bool { self.shared.key_mode != "none" }
    pub fn fail(&self, message: &str) { self.shared.fail(message, io::ErrorKind::Other, false); }
    pub fn configure(&self, action: impl FnOnce(&mut WsStream)) {
        match self.shared.io.lock() { Ok(mut io) => action(&mut io), Err(_) => self.fail("WebSocket state unavailable") }
    }
    pub fn send(&mut self, bytes: Bytes, encrypt: bool, video: bool, terminal: bool, timeout: u64) -> io::Result<()> {
        if let Some(failure) = self.shared.failure() { return Err(failure.error()); }
        if self.shared.closing.load(Ordering::Acquire) {
            return if terminal { Ok(()) } else { Err(io::Error::new(io::ErrorKind::BrokenPipe, "Desktop transport closing")) };
        }
        let admit = || -> io::Result<Outbound> {
            let maximum = if terminal { TERMINAL_BYTES } else { BYTE_BUDGET };
            if bytes.len() > maximum { return Err(io::Error::new(io::ErrorKind::InvalidData, "Desktop message exceeds its byte budget")); }
            let video_credit = if video {
                if self.shared.video_inflight.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, "Desktop video credit unavailable"));
                }
                Some(VideoCredit(self.shared.clone()))
            } else { None };
            let bytes_budget = if video { &self.shared.video_bytes } else if terminal { &self.shared.terminal_bytes } else { &self.shared.control_bytes };
            let bytes_permit = bytes_budget.clone().try_acquire_many_owned(bytes.len() as u32)
                .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "Desktop outstanding byte budget exhausted"))?;
            let count = if video || terminal { None } else { Some(self.shared.control_count.clone().try_acquire_owned()
                .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "Desktop control queue exhausted"))?) };
            let sequence = self.sequence.checked_add(1).ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Desktop sequence exhausted"))?;
            Ok(Outbound { bytes, encrypt, terminal, sequence, queued:Instant::now(), timeout,
                _bytes:bytes_permit, _count:count, video:video_credit })
        };
        let result = admit().and_then(|packet| {
            let sequence = packet.sequence;
            if terminal { self.shared.closing.store(true, Ordering::Release); }
            self.tx.try_send(packet).map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "Desktop writer unavailable"))?;
            self.sequence = sequence;
            self.shared.admitted.store(sequence, Ordering::Relaxed);
            Ok(())
        });
        if let Err(error) = &result { self.shared.fail(error, error.kind(), false); }
        result
    }
    pub async fn next(&mut self) -> Option<Result<BytesMut, io::Error>> {
        loop {
            if let Some(failure) = self.shared.failure() { return if failure.eof { None } else { Some(Err(failure.error())) }; }
            tokio::select! { biased;
                _ = self.failure.changed() => {},
                packet = self.rx.recv() => {
                    if let Some(failure) = self.shared.failure() { return if failure.eof { None } else { Some(Err(failure.error())) }; }
                    let packet = packet?;
                    self.shared.delivered.fetch_add(1, Ordering::Relaxed);
                    return Some(Ok(packet.bytes));
                }
            }
        }
    }
    pub async fn shutdown(&mut self, timeout_ms: u64) -> io::Result<()> {
        // Retire queued plaintext before encryption. An already committed record
        // must finish or fail; its cipher state is never resumed on another stream.
        self.shared.closing.store(true, Ordering::Release);
        let target = self.sequence;
        let drain = async {
            while *self.written.borrow() < target {
                if let Some(failure) = self.shared.failure() { return Err(failure.error()); }
                tokio::select! { biased;
                    _ = self.failure.changed() => {},
                    result = self.written.changed() => { result.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Desktop writer ended"))?; }
                }
            }
            Ok(())
        };
        let result = match tokio::time::timeout(Duration::from_millis(timeout_ms.clamp(1000, 120_000)), drain).await {
            Ok(result) => result, Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "Desktop writer drain timed out")),
        };
        self.shared.fail("Desktop transport closed", io::ErrorKind::ConnectionAborted, true);
        if let Some(reader) = &self.reader { reader.abort(); }
        if let Some(writer) = &self.writer { writer.abort(); }
        let reader = self.reader.take(); let writer = self.writer.take();
        let joins = async { if let Some(reader) = reader { let _ = reader.await; } if let Some(writer) = writer { let _ = writer.await; } };
        if tokio::time::timeout(Duration::from_secs(2), joins).await.is_err() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "Desktop transport cancellation did not settle"));
        }
        result
    }
}
impl Drop for Duplex {
    fn drop(&mut self) {
        self.shared.fail("Desktop transport dropped", io::ErrorKind::ConnectionAborted, true);
        if let Some(reader) = &self.reader { reader.abort(); }
        if let Some(writer) = &self.writer { writer.abort(); }
    }
}

async fn read(shared: Arc<Shared>, mut cipher: Option<Encrypt>, incoming: mpsc::Sender<Inbound>) {
    let mut io = Io(shared.io.clone()); let mut failure = shared.failure.subscribe();
    loop {
        if shared.failure().is_some() { return; }
        let next = tokio::select! { biased; _ = failure.changed() => { continue; }, next = io.next() => next };
        let data = match next {
            Some(Ok(WsMessage::Binary(data))) => {
                let mut data = BytesMut::from(&data[..]);
                if let Some(cipher) = &mut cipher { if let Err(error) = cipher.dec(&mut data) { shared.fail(&error, error.kind(), false); return; } }
                data
            }
            Some(Ok(WsMessage::Text(text))) if cipher.is_none() => BytesMut::from(text.as_bytes()),
            Some(Ok(WsMessage::Text(_))) => { shared.fail("WebSocket text after encryption", io::ErrorKind::InvalidData, false); return; }
            Some(Ok(WsMessage::Close(_))) | None => { shared.fail("WebSocket peer closed", io::ErrorKind::UnexpectedEof, true); return; }
            Some(Ok(_)) => continue,
            Some(Err(error)) => { shared.fail(error, io::ErrorKind::Other, false); return; }
        };
        if data.len() > BYTE_BUDGET { shared.fail("Desktop receive budget exceeded", io::ErrorKind::InvalidData, false); return; }
        shared.received.fetch_add(1, Ordering::Relaxed);
        let permit = tokio::select! { biased; _ = failure.changed() => { continue; },
            permit = shared.receive_bytes.clone().acquire_many_owned(data.len() as u32) => permit };
        let Ok(permit) = permit else { return; };
        let packet = Inbound { bytes:data, _bytes:permit };
        tokio::select! { biased; _ = failure.changed() => { return; },
            result = incoming.send(packet) => { if result.is_err() { return; } }
        }
    }
}

async fn write(shared: Arc<Shared>, mut cipher: Option<Encrypt>, mut outgoing: mpsc::Receiver<Outbound>) {
    let mut io = Io(shared.io.clone()); let mut failure = shared.failure.subscribe();
    loop {
        if shared.failure().is_some() { return; }
        let packet = tokio::select! { biased; _ = failure.changed() => { continue; }, packet = outgoing.recv() => packet };
        let Some(packet) = packet else { return; };
        if shared.closing.load(Ordering::Acquire) && !packet.terminal {
            shared.retired_packets.fetch_add(1, Ordering::Relaxed);
            shared.written.send_replace(packet.sequence);
            continue;
        }
        let writing = Instant::now(); let queued = packet.queued.elapsed();
        if packet.video.is_some() { shared.video_writing.store(true, Ordering::Relaxed); }
        let send = async {
            let deadline = if packet.timeout == 0 { None } else { Some(Duration::from_millis(packet.timeout)) };
            if deadline.is_some_and(|limit| queued >= limit) { return Err(io::Error::new(io::ErrorKind::TimedOut, "Desktop write expired in queue")); }
            let send = async {
                if packet.video.is_some() { let delay = shared.delay(); if !delay.is_zero() { tokio::time::sleep(delay).await; } }
                if shared.closing.load(Ordering::Acquire) && !packet.terminal { return Ok(false); }
                let bytes = if packet.encrypt {
                    match cipher.as_mut() { Some(cipher) => Bytes::from(cipher.enc(&packet.bytes)), None => packet.bytes.clone() }
                } else { packet.bytes.clone() };
                io.send(WsMessage::Binary(bytes)).await.map(|_| true).map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))
            };
            if let Some(limit) = deadline {
                tokio::time::timeout(limit.saturating_sub(queued), send).await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Desktop write timed out"))?
            } else { send.await }
        };
        let result = tokio::select! { biased; _ = failure.changed() => { return; }, result = send => result };
        if packet.video.is_some() && !matches!(result, Ok(false)) { if let Some(observer) = &shared.observer { observer(VideoTiming { queued, writing:writing.elapsed() }); } }
        if let Err(error) = result { shared.fail(&error, error.kind(), false); return; }
        if matches!(result, Ok(true)) { shared.written_packets.fetch_add(1, Ordering::Relaxed); }
        else { shared.retired_packets.fetch_add(1, Ordering::Relaxed); }
        shared.written.send_replace(packet.sequence);
        // Releasing packet-owned permits also releases the single video credit.
        drop(packet);
    }
}
