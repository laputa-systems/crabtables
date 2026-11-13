use std::io;
use std::thread::JoinHandle;
use std::time::Duration;

use netlink_sys::{Socket as NlSocket, SocketAddr, protocols::NETLINK_NETFILTER};

use crate::batch::{Batch, BatchOutcome};
use crate::error::{Error, Result};
use crate::nl::{Messages, Writer};
use crate::objects::Table;
use crate::types::Family;
use crate::sys::*;

pub(crate) fn err_msg(reply_seq: u32, req_seq: u32, errno: i32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&36u32.to_ne_bytes());
    v.extend_from_slice(&NLMSG_ERROR.to_ne_bytes());
    v.extend_from_slice(&0u16.to_ne_bytes());
    v.extend_from_slice(&reply_seq.to_ne_bytes());
    v.extend_from_slice(&0u32.to_ne_bytes());
    v.extend_from_slice(&(-errno).to_ne_bytes());
    v.extend_from_slice(&16u32.to_ne_bytes());
    v.extend_from_slice(&0u16.to_ne_bytes());
    v.extend_from_slice(&0u16.to_ne_bytes());
    v.extend_from_slice(&req_seq.to_ne_bytes());
    v.extend_from_slice(&0u32.to_ne_bytes());
    v
}

pub(crate) fn newgen_msg(seq: u32, id: u32) -> Vec<u8> {
    let mut w = Writer::new();
    let ty = (u16::from(NFNL_SUBSYS_NFTABLES) << 8) | u16::from(NFT_MSG_NEWGEN);
    let m = w.begin_msg(ty, 0, seq, 0, 0);
    w.put_be32(NFTA_GEN_ID, id);
    w.end_msg(m);
    w.into_bytes()
}

pub(crate) fn one_table_batch() -> Batch {
    let mut b = Batch::new();
    b.add_table(&Table::new(Family::Inet, "a"));
    b
}

/// What the stand-in for the kernel answers to the batch and the sentinel.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Scenario {
    Committed,
    Rejected,
    RejectedThenTruncated,
    TruncatedReply,
    OversizedDatagram,
    SentinelFailed,
    NoSentinelReply,
}

pub(crate) const ALL: [Scenario; 7] = [
    Scenario::Committed,
    Scenario::Rejected,
    Scenario::RejectedThenTruncated,
    Scenario::TruncatedReply,
    Scenario::OversizedDatagram,
    Scenario::SentinelFailed,
    Scenario::NoSentinelReply,
];

/// A userspace netlink socket answering a client's batch and sentinel the
/// way a faulty kernel connection would.
pub(crate) struct Peer {
    sock: NlSocket,
    portid: u32,
}

impl Peer {
    pub(crate) fn new() -> Self {
        let mut sock = NlSocket::new(NETLINK_NETFILTER).unwrap();
        let portid = sock.bind_auto().unwrap().port_number();
        Peer { sock, portid }
    }

    pub(crate) fn addr(&self) -> SocketAddr {
        SocketAddr::new(self.portid, 0)
    }

    pub(crate) fn serve(self, sc: Scenario) -> JoinHandle<()> {
        std::thread::spawn(move || {
            let mut buf = Vec::with_capacity(1 << 16);
            let (_, client) = self.sock.recv_from(&mut buf, 0).unwrap();
            let begin = Messages::new(&buf).next().unwrap().unwrap().seq;
            let op = begin.wrapping_add(1);
            let send = |d: &[u8]| {
                self.sock.send_to(d, &client, 0).unwrap();
            };
            match sc {
                Scenario::Committed => send(&err_msg(op, op, 0)),
                Scenario::Rejected => send(&err_msg(op, op, libc::ENOENT)),
                Scenario::RejectedThenTruncated => {
                    send(&err_msg(op, op, libc::ENOENT));
                    let mut t = err_msg(op, op, 0);
                    t.truncate(30);
                    send(&t);
                }
                Scenario::TruncatedReply => {
                    let mut t = err_msg(op, op, 0);
                    t.truncate(30);
                    send(&t);
                }
                Scenario::OversizedDatagram => {
                    let mut d = err_msg(op, op, 0);
                    d.resize(100_000, 0);
                    d[..4].copy_from_slice(&36u32.to_ne_bytes());
                    send(&d);
                }
                Scenario::SentinelFailed | Scenario::NoSentinelReply => {}
            }
            buf.clear();
            if self.sock.recv_from(&mut buf, 0).is_err() {
                return;
            }
            let sentinel = Messages::new(&buf).next().unwrap().unwrap().seq;
            match sc {
                Scenario::SentinelFailed => send(&err_msg(sentinel, sentinel, libc::EPERM)),
                Scenario::NoSentinelReply => {}
                _ => send(&newgen_msg(sentinel, 9)),
            }
        })
    }
}

pub(crate) const TIMEOUT: Duration = Duration::from_millis(500);

/// The outcome every transport must report for `sc`, the sync and the async
/// one alike.
pub(crate) fn expect(sc: Scenario, r: Result<BatchOutcome>) {
    let ctx = format!("{sc:?}: {r:?}");
    let e = match (sc, r) {
        (Scenario::Committed, Ok(o)) => {
            assert_eq!(o.genid, 9);
            return;
        }
        (_, Ok(_)) => panic!("{ctx}"),
        (_, Err(e)) => e,
    };
    match sc {
        Scenario::Committed => panic!("{ctx}"),
        Scenario::Rejected | Scenario::RejectedThenTruncated => {
            let b = e.as_batch().expect(&ctx);
            assert_eq!(b.errors.len(), 1, "{ctx}");
            assert_eq!(b.errors[0].errno, libc::ENOENT, "{ctx}");
            assert_eq!(b.responses_lost, matches!(sc, Scenario::RejectedThenTruncated));
            assert!(!e.is_outcome_unknown());
        }
        _ => {
            let u = e.as_outcome_unknown().expect(&ctx);
            match (sc, u.cause()) {
                (Scenario::TruncatedReply, Error::Malformed(_)) => {}
                (Scenario::OversizedDatagram, Error::Io(io))
                    if io.kind() == io::ErrorKind::InvalidData => {}
                (Scenario::SentinelFailed, Error::Kernel(k)) if k.errno == libc::EPERM => {}
                (Scenario::NoSentinelReply, Error::Io(io))
                    if io.kind() == io::ErrorKind::WouldBlock => {}
                (_, c) => panic!("{ctx}: cause {c:?}"),
            }
            assert!(e.as_batch().is_none(), "{ctx}");
            assert_eq!(e.errno(), None, "{ctx}");
            assert!(!e.is_not_found() && !e.is_exists() && !e.is_generation_mismatch());
            assert!(std::error::Error::source(&e).is_some());
            assert!(e.to_string().contains("outcome unknown"), "{e}");
        }
    }
}
