//! Transport adapters.
//!
//! Both transports carry identical protocol frames. A transport is responsible
//! for moving bytes and for nothing else: it never inspects the payload to make
//! a security decision, and it never learns a credential. That is what makes
//! "switch from Wi-Fi to Bluetooth" a configuration change rather than a
//! redesign (`PROTOCOL.md` §13).

pub mod ble;
pub mod wifi;

use std::sync::Arc;

use rba_protocol::errors::{ProtocolError, Result};
use rba_protocol::frame::{AsyncFrameWriter, AsyncFrames, Frame, FrameError};
use rba_protocol::messages::Message;
use rba_protocol::types::{Id, Transport};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::engine::Engine;
use rba_protocol::pairing::PairingResult;

/// Time allowed for the peer to send `SESSION_HELLO_ACK`.
const SESSION_SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Idle limit between frames. Authentication may legitimately wait for a human
/// fingerprint and confirmation, so this is longer than the default auth timeout
/// but still bounds a stalled connection.
const FRAME_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

/// One accepted device connection.
///
/// Generic over the byte stream so the Wi-Fi (TLS) and BLE (GATT) adapters share
/// this state machine verbatim.
pub struct Connection<R, W> {
    pub engine: Arc<Engine>,
    pub reader: AsyncFrames<R>,
    pub writer: AsyncFrameWriter<W>,
    pub transport: Transport,
    pub peer: String,
    session_id: Id,
    device_id: Option<Id>,
    /// Which connection this task registered, so its teardown only unregisters that
    /// connection and not a newer one for the same device.
    conn_id: Option<u64>,
}

/// A connection over any transport, with the stream already split.
pub type SplitConnection<S> = Connection<tokio::io::ReadHalf<S>, tokio::io::WriteHalf<S>>;

/// Opens a connection over any stream type. The protocol state machine in
/// [`Connection::run`] is shared verbatim by every transport.
pub fn open<S>(
    engine: Arc<Engine>,
    stream: S,
    transport: Transport,
    peer: String,
) -> SplitConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (reader, writer) = tokio::io::split(stream);
    Connection {
        engine,
        reader: AsyncFrames::new(reader),
        writer: AsyncFrameWriter::new(writer),
        transport,
        peer,
        session_id: Id::default(),
        device_id: None,
        conn_id: None,
    }
}

impl<R, W> Connection<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send,
{
    async fn send(&mut self, frame: &Frame) -> std::result::Result<(), FrameError> {
        self.writer.write_frame(frame).await
    }

    async fn send_error(&mut self, e: &ProtocolError, request_id: Option<Id>) {
        let msg = Message::Error(rba_protocol::types::ErrorMsg::from_error(e, request_id));
        let _ = self.send(&msg.to_frame()).await;
    }

    /// Runs the whole host-side session for one connection.
    pub async fn run(mut self, pairing_timeout: u64) -> Result<()> {
        let session_id = Id::random()?;
        let host_nonce = rba_protocol::crypto::random_array()?;
        self.session_id = session_id;

        // 1. Host always opens with SESSION_HELLO. Keep the struct so the
        //    registration check later compares against the same values the
        //    peer saw.
        let hello = self.engine.session_hello(session_id, host_nonce);
        let hello_frame = Message::SessionHello(hello.clone()).to_frame();
        let _ = self.send(&hello_frame).await;

        // 2. The peer must answer with SESSION_HELLO_ACK.
        let first = match tokio::time::timeout(SESSION_SETUP_TIMEOUT, self.read_message()).await {
            Ok(Ok(Some(m))) => m,
            Ok(Ok(None)) => return Ok(()),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(()),
        };
        let ack = match first {
            Message::SessionHelloAck(a) => a,
            other => {
                self.send_error(
                    &ProtocolError::BadRequest(format!(
                        "expected SESSION_HELLO_ACK, got {}",
                        other.name()
                    )),
                    None,
                )
                .await;
                return Ok(());
            }
        };

        // 3. If pairing is open, this connection is a pairing attempt. The pairing
        //    task runs *alongside* the read loop below rather than instead of it:
        //    it needs the device's `PAIRING_SUBMIT` to be read and delivered while
        //    it waits.
        let pairing_mode = self.engine.pairing_active();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Frame>();
        if pairing_mode {
            self.engine
                .audit()
                .write(&crate::audit::Event::new("pairing_connection"));
            let engine = self.engine.clone();
            let sid = session_id;
            let tx_for_pairing = tx.clone();
            tokio::spawn(async move {
                let outcome = engine.drive_pairing(&tx_for_pairing, pairing_timeout).await;
                match outcome {
                    Ok(result) => {
                        let msg = Message::PairingResult(result);
                        let _ = tx_for_pairing.send(msg.to_frame());
                    }
                    Err(e) => {
                        let ev = crate::audit::Event::new("pairing_failed")
                            .denied(e.code().as_str())
                            .detail(e.to_string());
                        engine.audit().write(&ev);
                        let reject = Message::PairingResult(PairingResult {
                            session_id: sid,
                            status: 1,
                            host_mac: None,
                            revocation_token: None,
                        });
                        let _ = tx_for_pairing.send(reject.to_frame());
                        let err =
                            Message::Error(rba_protocol::types::ErrorMsg::from_error(&e, None));
                        let _ = tx_for_pairing.send(err.to_frame());
                    }
                }
            });
        } else {
            let handle = match self
                .engine
                .register_device(&hello, &ack, tx, self.transport)
            {
                Ok(h) => h,
                Err(e) => {
                    self.send_error(&e, None).await;
                    return Ok(());
                }
            };
            self.device_id = Some(handle.device_id);
            self.conn_id = Some(handle.conn_id);
        }

        // 4. Serve until the peer disconnects or a protocol error occurs.
        let mut outbound = rx;
        let mut sent_pairing_result: Option<Id> = None;
        loop {
            tokio::select! {
                biased;
                frame = outbound.recv() => {
                    match frame {
                        Some(f) => {
                            if self.send(&f).await.is_err() {
                                break;
                            }
                            if pairing_mode {
                                if let Ok(Message::PairingResult(result)) = Message::from_frame(&f) {
                                    if result.status == 0 {
                                        sent_pairing_result = Some(result.session_id);
                                    }
                                }
                            }
                        }
                        None => {
                            // Every sender is gone: nothing more can be sent.
                            break;
                        }
                    }
                }
                frame = tokio::time::timeout(FRAME_READ_TIMEOUT, self.reader.next_frame()) => {
                    match frame {
                        Err(_) => break,   // stalled connection: fail closed
                        Ok(Err(_)) => break,   // fail closed on any framing error
                        Ok(Ok(None)) => break,  // clean disconnect
                        Ok(Ok(Some(f))) => {
                            match Message::from_frame(&f) {
                                // A pairing submission is routed without needing a
                                // registered device identity.
                                Ok(Message::PairingSubmit(submit)) => {
                                    self.engine.deliver_pairing(submit);
                                }
                                // The device persists its record after receiving
                                // PAIRING_RESULT, then sends this acknowledgement.
                                // It is bound to the session that just completed.
                                Ok(Message::PairingConfirmed(confirm)) => {
                                    if sent_pairing_result.take() != Some(confirm.session_id) {
                                        self.send_error(&ProtocolError::ContextMismatch(
                                            "pairing acknowledgement does not match this connection".into(),
                                        ), None).await;
                                        break;
                                    }
                                    match self.engine.acknowledge_pairing(&confirm.session_id) {
                                        Ok(()) => {
                                            self.engine.audit().write(
                                                &crate::audit::Event::new("pairing_acknowledged")
                                                    .success(),
                                            );
                                        }
                                        Err(e) => {
                                            let ev = crate::audit::Event::new("pairing_rejected")
                                                .denied(e.code().as_str())
                                                .detail(e.to_string());
                                            self.engine.audit().write(&ev);
                                            self.send_error(&e, None).await;
                                            break;
                                        }
                                    }
                                }
                                // A device may revoke itself with the bearer token
                                // issued at pairing. This works after local unpair,
                                // when the device no longer has a host record.
                                Ok(Message::Unpair(unpair)) => {
                                    match self.engine.revoke_by_token(&unpair.token) {
                                        Ok(Some(_)) => break,
                                        Ok(None) => {
                                            self.send_error(&ProtocolError::NotPaired, None).await;
                                            break;
                                        }
                                        Err(e) => {
                                            self.send_error(&e, None).await;
                                            break;
                                        }
                                    }
                                }
                                Ok(m) => match self.device_id {
                                    Some(d) => self.engine.deliver(&d, m),
                                    None => {
                                        // Still pairing: anything else is unexpected.
                                        let ev = crate::audit::Event::new("unsolicited_message")
                                            .denied("CONTEXT_MISMATCH");
                                        self.engine.audit().write(&ev);
                                        break;
                                    }
                                },
                                Err(e) => {
                                    self.send_error(&e, None).await;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        if let (Some(d), Some(c)) = (self.device_id, self.conn_id) {
            self.engine.disconnect_device(&d, c);
        }
        Ok(())
    }

    /// Reads and decodes one message, logging and returning `None` on error.
    async fn read_message(&mut self) -> Result<Option<Message>> {
        match self.reader.next_frame().await {
            Ok(Some(f)) => match Message::from_frame(&f) {
                Ok(m) => Ok(Some(m)),
                Err(e) => {
                    self.send_error(&e, None).await;
                    Err(e)
                }
            },
            Ok(None) => Ok(None),
            Err(_) => Err(ProtocolError::BadRequest("framing error".into())),
        }
    }
}
