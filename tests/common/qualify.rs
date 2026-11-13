#![allow(dead_code)]
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::common::NetnsThread;
use crabtables::{Batch, Socket};

pub const DELIVER_MS: u64 = 4000;
pub const SILENCE_MS: u64 = 300;
pub const FENCE_MS: u64 = 4000;
pub const COMMAND_MS: u64 = 60_000;
pub const CANARY_BUDGET: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fam {
    V4,
    V6,
}

impl Fam {
    pub fn tag(self) -> &'static str {
        match self {
            Fam::V4 => "v4",
            Fam::V6 => "v6",
        }
    }

    pub fn table(self) -> &'static str {
        match self {
            Fam::V4 => "ip",
            Fam::V6 => "ip6",
        }
    }

    fn v6(last: u16, net: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0xfd00, net, 0, 0, 0, 0, 0, last))
    }

    pub fn client(self, i: usize) -> IpAddr {
        match self {
            Fam::V4 => IpAddr::V4(Ipv4Addr::new(10, 1, 0, [2, 3, 130, 205][i])),
            Fam::V6 => Self::v6([2, 3, 0x82, 0xcd][i], 1),
        }
    }

    pub fn router_c(self) -> IpAddr {
        match self {
            Fam::V4 => IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1)),
            Fam::V6 => Self::v6(1, 1),
        }
    }

    pub fn router_s(self) -> IpAddr {
        match self {
            Fam::V4 => IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1)),
            Fam::V6 => Self::v6(1, 2),
        }
    }

    pub fn server(self, i: usize) -> IpAddr {
        match self {
            Fam::V4 => IpAddr::V4(Ipv4Addr::new(10, 2, 0, [2, 3][i])),
            Fam::V6 => Self::v6([2, 3][i], 2),
        }
    }

    pub fn pool(self) -> IpAddr {
        match self {
            Fam::V4 => IpAddr::V4(Ipv4Addr::new(10, 9, 0, 100)),
            Fam::V6 => Self::v6(0x100, 9),
        }
    }

    pub fn unspecified(self) -> IpAddr {
        match self {
            Fam::V4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Fam::V6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
    }

    pub fn hp(self, a: IpAddr, port: impl std::fmt::Display) -> String {
        match self {
            Fam::V4 => format!("{a}:{port}"),
            Fam::V6 => format!("[{a}]:{port}"),
        }
    }

    fn plen(self) -> u8 {
        match self {
            Fam::V4 => 24,
            Fam::V6 => 64,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn name(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bind {
    Srv(usize),
    RouterC,
    Any,
}

impl Bind {
    fn label(self) -> String {
        match self {
            Bind::Srv(i) => format!("srv{i}"),
            Bind::RouterC => "routerc".into(),
            Bind::Any => "routerany".into(),
        }
    }

    fn addr(self, f: Fam) -> IpAddr {
        match self {
            Bind::Srv(i) => f.server(i),
            Bind::RouterC => f.router_c(),
            Bind::Any => f.unspecified(),
        }
    }

    fn on_router(self) -> bool {
        !matches!(self, Bind::Srv(_))
    }
}

pub fn sink_name(proto: Proto, bind: Bind, port: u16) -> String {
    format!("{}/{}:{}", proto.name(), bind.label(), port)
}

#[derive(Clone, Debug)]
pub struct SinkSpec {
    pub name: String,
    pub proto: Proto,
    pub bind: Bind,
    pub port: u16,
    pub echo: bool,
    pub fence: bool,
}

impl SinkSpec {
    pub fn new(proto: Proto, bind: Bind, port: u16, echo: bool) -> Self {
        SinkSpec {
            name: sink_name(proto, bind, port),
            proto,
            bind,
            port,
            echo,
            fence: false,
        }
    }

    pub fn fence(bind: Bind, port: u16) -> Self {
        SinkSpec {
            fence: true,
            ..SinkSpec::new(Proto::Udp, bind, port, false)
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Where {
    Srv(usize),
    RouterC,
    RouterS,
}

impl Where {
    fn addr(self, f: Fam) -> IpAddr {
        match self {
            Where::Srv(i) => f.server(i),
            Where::RouterC => f.router_c(),
            Where::RouterS => f.router_s(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Origin {
    Client(usize),
    Router,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PeerPort {
    Same,
    Exact(u16),
    Range(u16, u16),
}

#[derive(Clone, Debug)]
pub enum Want {
    Blocked,
    Refused,
    Delivered {
        at: String,
        peer: Option<IpAddr>,
        port: PeerPort,
    },
}

impl Want {
    pub fn at(proto: Proto, bind: Bind, port: u16, peer: IpAddr, pp: PeerPort) -> Want {
        Want::Delivered {
            at: sink_name(proto, bind, port),
            peer: Some(peer),
            port: pp,
        }
    }

    pub fn anywhere(proto: Proto, bind: Bind, port: u16) -> Want {
        Want::Delivered {
            at: sink_name(proto, bind, port),
            peer: None,
            port: PeerPort::Same,
        }
    }

    fn delivered(&self) -> bool {
        matches!(self, Want::Delivered { .. })
    }
}

#[derive(Clone, Debug)]
pub struct Probe {
    pub name: String,
    pub from: Origin,
    pub proto: Proto,
    pub dst: (Where, u16),
    pub sport: u16,
    pub mark: u32,
    pub hold: bool,
    pub want: Want,
}

#[derive(Clone, Debug)]
pub struct Dgram {
    pub src: usize,
    pub sport: u16,
    pub dport: u16,
    pub mark: u32,
    pub want: bool,
}

#[derive(Clone, Debug)]
pub struct Burst {
    pub label: &'static str,
    pub from: Origin,
    pub dst: Where,
    pub dgrams: Vec<Dgram>,
    pub fence: String,
    pub fence_port: u16,
}

#[derive(Clone)]
pub struct Ruleset {
    pub label: &'static str,
    pub text: String,
    pub typed: Option<fn(Fam) -> Batch>,
    pub ok: bool,
}

#[derive(Clone)]
pub struct Cli {
    pub label: &'static str,
    pub args: Vec<&'static str>,
    pub files: Vec<(&'static str, String)>,
    pub stdin: Option<&'static str>,
    pub ok: bool,
    pub stdout: bool,
    pub reference_may_crash: bool,
}

#[derive(Clone)]
pub struct Replace {
    pub policy: Ruleset,
    pub canary: String,
    pub canary_port: u16,
    pub fence: String,
    pub fence_port: u16,
}

#[derive(Clone, Debug, Default)]
pub struct SnapSpec {
    pub label: &'static str,
    pub counters: Vec<(&'static str, u64)>,
    pub conntrack: bool,
    pub tuples: Vec<Vec<String>>,
    pub absent: Vec<Vec<String>>,
    pub nat_ports: Vec<(Vec<String>, u16, u16)>,
    pub hide_ct: Vec<String>,
    pub lister: bool,
}

#[derive(Clone)]
pub enum Step {
    Install(Ruleset),
    Cli(Cli),
    Probe(Probe),
    Burst(Burst),
    Send {
        name: &'static str,
        want: bool,
    },
    Snap(SnapSpec),
    Replace(Replace),
    Same(&'static str, &'static str),
}

#[derive(Clone)]
pub struct Case {
    pub id: String,
    pub row: &'static str,
    pub fam: Fam,
    pub sinks: Vec<SinkSpec>,
    pub steps: Vec<Step>,
    pub known: Option<&'static str>,
    pub generated: Option<(u64, usize)>,
}

impl Case {
    fn has_typed(&self) -> bool {
        let mut any = false;
        for s in &self.steps {
            match s {
                Step::Install(p) => {
                    if p.typed.is_none() {
                        return false;
                    }
                    any = true;
                }
                Step::Cli(_) | Step::Replace(_) => return false,
                _ => {}
            }
        }
        any
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Front {
    Nft,
    Nfcrt,
    Typed,
}

impl Front {
    pub fn name(self) -> &'static str {
        match self {
            Front::Nft => "nft",
            Front::Nfcrt => "nfcrt",
            Front::Typed => "typed",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fault {
    DropNat,
    UnmaskConcat,
    SplitReplace,
}

impl Fault {
    pub fn parse(s: &str) -> Option<Fault> {
        match s {
            "drop-nat" => Some(Fault::DropNat),
            "unmask-concat" => Some(Fault::UnmaskConcat),
            "split-replace" => Some(Fault::SplitReplace),
            _ => None,
        }
    }

    fn apply(self, text: &str) -> String {
        match self {
            Fault::DropNat => text
                .lines()
                .filter(|l| {
                    !(l.contains(" dnat to")
                        || l.contains(" snat to")
                        || l.contains("masquerade")
                        || l.contains("redirect to"))
                })
                .collect::<Vec<_>>()
                .join("\n"),
            Fault::UnmaskConcat => text.replace(" and 255", ""),
            Fault::SplitReplace => text.to_string(),
        }
    }
}

pub struct Out {
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Out {
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }

    fn status(&self) -> String {
        match (self.code, self.signal) {
            (Some(c), _) => format!("exit {c}"),
            (None, Some(s)) => format!("signal {s}"),
            _ => "unknown".into(),
        }
    }
}

pub fn exec(ns: &NetnsThread, prog: &str, args: &[&str], dir: Option<&Path>, stdin: Option<&str>) -> Out {
    let prog = prog.to_string();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let dir = dir.map(|d| d.to_path_buf());
    let stdin = stdin.map(|s| s.as_bytes().to_vec());
    ns.run(move || {
        let mut c = Command::new(&prog);
        c.args(&args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(d) = &dir {
            c.current_dir(d);
        }
        let mut child = match c.spawn() {
            Ok(c) => c,
            Err(e) => {
                return Out {
                    code: None,
                    signal: None,
                    stdout: String::new(),
                    stderr: format!("spawn {prog}: {e}"),
                };
            }
        };
        let pid = child.id() as i32;
        let writer = stdin.map(|data| {
            let mut w = child.stdin.take().unwrap();
            std::thread::spawn(move || {
                let _ = w.write_all(&data);
            })
        });
        let (done_tx, done_rx) = channel::<()>();
        let watchdog = std::thread::spawn(move || {
            if done_rx
                .recv_timeout(Duration::from_millis(COMMAND_MS))
                .is_err()
            {
                // SAFETY: signalling a child process owned by this call.
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        });
        let o = child.wait_with_output();
        drop(done_tx);
        let _ = watchdog.join();
        if let Some(w) = writer {
            let _ = w.join();
        }
        let o = o.unwrap();
        use std::os::unix::process::ExitStatusExt;
        Out {
            code: o.status.code(),
            signal: o.status.signal(),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    })
}

fn ns_id() -> String {
    std::fs::read_link("/proc/thread-self/ns/net")
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|e| format!("unreadable: {e}"))
}

fn write_proc(path: &str, v: &str) -> Result<(), String> {
    std::fs::write(path, v).map_err(|e| format!("write {path}: {e}"))
}

fn ipc(ns: &NetnsThread, args: &str) -> Result<(), String> {
    let o = exec(ns, "ip", &args.split_whitespace().collect::<Vec<_>>(), None, None);
    if o.ok() {
        Ok(())
    } else {
        Err(format!("ip {args}: {}", o.stderr.trim()))
    }
}

pub struct World {
    pub front: Front,
    pub fam: Fam,
    pub client: NetnsThread,
    pub router: NetnsThread,
    pub server: NetnsThread,
    pub dir: PathBuf,
    pub ns: [String; 3],
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl World {
    pub fn build(front: Front, fam: Fam, dir: PathBuf) -> Result<World, String> {
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let host = ns_id();
        let client = NetnsThread::new();
        let router = NetnsThread::new();
        let server = NetnsThread::new();
        let ns = [client.run(ns_id), router.run(ns_id), server.run(ns_id)];
        let mut all = vec![host.clone()];
        all.extend(ns.iter().cloned());
        let mut uniq = all.clone();
        uniq.sort();
        uniq.dedup();
        if uniq.len() != all.len() || all.iter().any(|n| n.starts_with("unreadable")) {
            return Err(format!("namespaces are not isolated: {all:?}"));
        }
        for n in [&client, &router, &server] {
            n.run(|| {
                write_proc("/proc/sys/net/ipv6/conf/default/accept_dad", "0")?;
                write_proc("/proc/sys/net/ipv6/conf/default/accept_ra", "0")
            })?;
        }
        router.run(|| {
            write_proc("/proc/sys/net/ipv4/ip_forward", "1")?;
            write_proc("/proc/sys/net/ipv6/conf/all/forwarding", "1")
        })?;
        ipc(&router, "link add c0 type veth peer name c1")?;
        ipc(&router, &format!("link set c1 netns {}", client.tid))?;
        ipc(&router, "link add s0 type veth peer name s1")?;
        ipc(&router, &format!("link set s1 netns {}", server.tid))?;
        let add = |ns: &NetnsThread, dev: &str, a: IpAddr, f: Fam| {
            let nodad = if f == Fam::V6 { " nodad" } else { "" };
            ipc(ns, &format!("addr add {a}/{} dev {dev}{nodad}", f.plen()))
        };
        for f in [Fam::V4, Fam::V6] {
            add(&router, "c0", f.router_c(), f)?;
            add(&router, "s0", f.router_s(), f)?;
            for i in 0..4 {
                add(&client, "c1", f.client(i), f)?;
            }
            for i in 0..2 {
                add(&server, "s1", f.server(i), f)?;
            }
        }
        for (ns, dev) in [(&router, "c0"), (&router, "s0"), (&client, "c1"), (&server, "s1")] {
            ipc(ns, &format!("link set {dev} up"))?;
        }
        for f in [Fam::V4, Fam::V6] {
            let v6 = if f == Fam::V6 { "-6 " } else { "" };
            ipc(&client, &format!("{v6}route add default via {}", f.router_c()))?;
            ipc(&server, &format!("{v6}route add default via {}", f.router_s()))?;
        }
        let w = World {
            front,
            fam,
            client,
            router,
            server,
            dir,
            ns,
        };
        for f in [Fam::V4, Fam::V6] {
            for i in 0..2 {
                warm(&w.client, f.client(0), f.server(i))?;
            }
            warm(&w.client, f.client(0), f.router_s())?;
            warm(&w.server, f.server(0), f.client(0))?;
        }
        let empty = w.nft_list()?;
        if !empty.trim().is_empty() {
            return Err(format!("new namespace has a ruleset: {empty}"));
        }
        Ok(w)
    }

    pub fn nft_list(&self) -> Result<String, String> {
        let o = exec(&self.router, "nft", &["list", "ruleset"], Some(&self.dir), None);
        if o.ok() {
            Ok(o.stdout)
        } else {
            Err(format!("nft list ruleset: {} {}", o.status(), o.stderr))
        }
    }

    pub fn nfcrt_list(&self) -> Result<String, String> {
        let o = exec(&self.router, nfcrt(), &["list", "ruleset"], Some(&self.dir), None);
        if o.ok() {
            Ok(o.stdout)
        } else {
            Err(format!("nfcrt list ruleset: {} {}", o.status(), o.stderr))
        }
    }

    fn conntrack(&self) -> Result<Vec<String>, String> {
        let o = exec(&self.router, "conntrack", &["-L"], Some(&self.dir), None);
        if !o.ok() {
            return Err(format!("conntrack -L: {} {}", o.status(), o.stderr));
        }
        let mut lines: Vec<String> = o
            .stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(norm_ct_line)
            .collect();
        lines.sort();
        Ok(lines)
    }
}

fn warm(ns: &NetnsThread, src: IpAddr, dst: IpAddr) -> Result<(), String> {
    ns.run(move || {
        let u = UdpSocket::bind(SocketAddr::new(src, 0)).map_err(|e| format!("warm bind {src}: {e}"))?;
        u.connect(SocketAddr::new(dst, 1)).map_err(|e| format!("warm connect {dst}: {e}"))?;
        u.set_read_timeout(Some(Duration::from_millis(DELIVER_MS))).unwrap();
        u.send(b"warm").map_err(|e| format!("warm send {src} -> {dst}: {e}"))?;
        match u.recv(&mut [0u8; 16]) {
            Err(e) if e.raw_os_error() == Some(libc::ECONNREFUSED) => Ok(()),
            other => Err(format!("warm-up {src} -> {dst}: expected port unreachable, got {other:?}")),
        }
    })
}

pub fn nfcrt() -> &'static str {
    env!("CARGO_BIN_EXE_nfcrt")
}

fn norm_ct_line(l: &str) -> String {
    let mut toks: Vec<&str> = l.split_whitespace().collect();
    if toks.len() > 2 && toks[1].parse::<u32>().is_ok() {
        toks.remove(2);
    }
    toks.retain(|t| !t.starts_with("use=") && !t.starts_with("id="));
    toks.join(" ")
}

pub fn mask_counters(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("packets ") {
        out.push_str(&rest[..i + 8]);
        rest = &rest[i + 8..];
        let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        out.push('_');
        rest = &rest[end..];
        if let Some(j) = rest.strip_prefix(" bytes ") {
            out.push_str(" bytes ");
            let end = j.find(|c: char| !c.is_ascii_digit()).unwrap_or(j.len());
            out.push('_');
            rest = &j[end..];
        }
    }
    out.push_str(rest);
    out
}

pub fn structural(listing: &str) -> String {
    let mut out = String::new();
    let mut rest = listing;
    while let Some(i) = rest.find("expires ") {
        out.push_str(&rest[..i + 8]);
        rest = &rest[i + 8..];
        let end = rest.find([' ', ',', '}', '\n']).unwrap_or(rest.len());
        out.push('_');
        rest = &rest[end..];
    }
    out.push_str(rest);
    mask_counters(&out)
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn counters_of(listing: &str) -> BTreeMap<String, u64> {
    let mut m = BTreeMap::new();
    for l in listing.lines() {
        let Some(i) = l.find("counter packets ") else {
            continue;
        };
        let n: u64 = l[i + 16..]
            .split_whitespace()
            .next()
            .and_then(|t| t.parse().ok())
            .unwrap_or(u64::MAX);
        if let Some(c) = l.find("comment \"") {
            let name = l[c + 9..].split('"').next().unwrap_or("");
            m.insert(name.to_string(), n);
        }
    }
    m
}

fn pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: fds has room for the two descriptors pipe2 writes.
    let r = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(r, 0, "pipe2: {}", std::io::Error::last_os_error());
    // SAFETY: both descriptors were just created and are owned here.
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

fn poll1(fds: &mut [libc::pollfd], timeout_ms: i32) -> i32 {
    // SAFETY: fds is a valid slice of pollfd.
    unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) }
}

fn pollfd(fd: RawFd) -> libc::pollfd {
    libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }
}

pub struct Seen {
    pub sink: String,
    pub peer: SocketAddr,
    pub local: SocketAddr,
    pub payload: Vec<u8>,
}

enum Endpoint {
    Tcp(TcpListener),
    Udp(UdpSocket),
}

struct Listening {
    name: String,
    echo: bool,
    fence: bool,
    ep: Endpoint,
}

impl Listening {
    fn fd(&self) -> RawFd {
        match &self.ep {
            Endpoint::Tcp(l) => l.as_raw_fd(),
            Endpoint::Udp(u) => u.as_raw_fd(),
        }
    }
}

pub struct Sinks {
    stop: Option<OwnedFd>,
    threads: Vec<JoinHandle<()>>,
    pub rx: Receiver<Seen>,
}

impl Drop for Sinks {
    fn drop(&mut self) {
        drop(self.stop.take());
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

fn serve(eps: Vec<Listening>, stop: Arc<OwnedFd>, tx: Sender<Seen>) {
    let mut handlers: Vec<JoinHandle<()>> = Vec::new();
    loop {
        let mut fds: Vec<libc::pollfd> = eps.iter().map(|e| pollfd(e.fd())).collect();
        fds.push(pollfd(stop.as_raw_fd()));
        if poll1(&mut fds, -1) < 0 {
            continue;
        }
        if fds[eps.len()].revents != 0 {
            break;
        }
        for fence_pass in [false, true] {
            for e in eps.iter().filter(|e| e.fence == fence_pass) {
                loop {
                    match &e.ep {
                        Endpoint::Tcp(l) => {
                            let Ok((s, peer)) = l.accept() else { break };
                            let local = s.local_addr().unwrap();
                            let _ = tx.send(Seen {
                                sink: e.name.clone(),
                                peer,
                                local,
                                payload: Vec::new(),
                            });
                            let stop = stop.clone();
                            let echo = e.echo;
                            handlers.push(std::thread::spawn(move || tcp_handler(s, stop, echo)));
                        }
                        Endpoint::Udp(u) => {
                            let mut buf = [0u8; 2048];
                            let Ok((n, peer)) = u.recv_from(&mut buf) else {
                                break;
                            };
                            let _ = tx.send(Seen {
                                sink: e.name.clone(),
                                peer,
                                local: u.local_addr().unwrap(),
                                payload: buf[..n].to_vec(),
                            });
                            if e.echo {
                                let _ = u.send_to(&buf[..n], peer);
                            }
                        }
                    }
                }
            }
        }
    }
    for h in handlers {
        let _ = h.join();
    }
}

fn tcp_handler(mut s: TcpStream, stop: Arc<OwnedFd>, echo: bool) {
    let mut buf = [0u8; 4096];
    loop {
        let mut fds = [pollfd(s.as_raw_fd()), pollfd(stop.as_raw_fd())];
        if poll1(&mut fds, -1) < 0 {
            continue;
        }
        if fds[1].revents != 0 {
            return;
        }
        match s.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if echo && s.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
        }
    }
}

pub fn start_sinks(w: &World, specs: &[SinkSpec]) -> Result<Sinks, String> {
    let (stop_r, stop_w) = pipe();
    let stop = Arc::new(stop_r);
    let (tx, rx) = channel();
    let mut threads = Vec::new();
    for on_router in [false, true] {
        let mine: Vec<SinkSpec> = specs
            .iter()
            .filter(|s| s.bind.on_router() == on_router)
            .cloned()
            .collect();
        if mine.is_empty() {
            continue;
        }
        let fam = w.fam;
        let ns = if on_router { &w.router } else { &w.server };
        let eps: Vec<Listening> = ns.run(move || {
            let mut v = Vec::new();
            for s in mine {
                let a = SocketAddr::new(s.bind.addr(fam), s.port);
                let ep = match s.proto {
                    Proto::Tcp => {
                        let l = TcpListener::bind(a).map_err(|e| format!("bind {} {a}: {e}", s.name))?;
                        l.set_nonblocking(true).map_err(|e| e.to_string())?;
                        Endpoint::Tcp(l)
                    }
                    Proto::Udp => {
                        let u = UdpSocket::bind(a).map_err(|e| format!("bind {} {a}: {e}", s.name))?;
                        u.set_nonblocking(true).map_err(|e| e.to_string())?;
                        Endpoint::Udp(u)
                    }
                };
                v.push(Listening {
                    name: s.name,
                    echo: s.echo,
                    fence: s.fence,
                    ep,
                });
            }
            Ok::<_, String>(v)
        })?;
        let (stop, tx) = (stop.clone(), tx.clone());
        threads.push(std::thread::spawn(move || serve(eps, stop, tx)));
    }
    Ok(Sinks {
        stop: Some(stop_w),
        threads,
        rx,
    })
}

fn sockaddr(a: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: sockaddr_storage is plain data for which all zeroes is valid.
    let mut st: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match a {
        SocketAddr::V4(a) => {
            let p = (&raw mut st).cast::<libc::sockaddr_in>();
            // SAFETY: sockaddr_storage is large and aligned enough for sockaddr_in.
            unsafe {
                *p = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: a.port().to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(a.ip().octets()),
                    },
                    sin_zero: [0; 8],
                };
            }
            std::mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(a) => {
            let p = (&raw mut st).cast::<libc::sockaddr_in6>();
            // SAFETY: sockaddr_storage is large and aligned enough for sockaddr_in6.
            unsafe {
                *p = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: a.port().to_be(),
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr {
                        s6_addr: a.ip().octets(),
                    },
                    sin6_scope_id: 0,
                };
            }
            std::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    (st, len as libc::socklen_t)
}

fn set_mark(fd: RawFd, mark: u32) -> Result<(), String> {
    if mark == 0 {
        return Ok(());
    }
    // SAFETY: setsockopt with a pointer to a u32 of the stated length.
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&raw const mark).cast(),
            4,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(format!("SO_MARK: {}", std::io::Error::last_os_error()))
    }
}

fn pin_cpu() {
    // SAFETY: sched_getcpu and sched_setaffinity on the calling thread with a local mask.
    unsafe {
        let cpu = libc::sched_getcpu();
        if cpu < 0 {
            return;
        }
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu as usize, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Outcome {
    Reply,
    Blocked,
    Refused,
    Reset,
    Error(String),
}

impl Outcome {
    fn name(&self) -> String {
        match self {
            Outcome::Reply => "reply".into(),
            Outcome::Blocked => "blocked".into(),
            Outcome::Refused => "refused".into(),
            Outcome::Reset => "reset".into(),
            Outcome::Error(e) => format!("error({e})"),
        }
    }
}

fn errno_outcome(e: &std::io::Error) -> Outcome {
    match e.raw_os_error() {
        Some(libc::ECONNREFUSED) => Outcome::Refused,
        Some(libc::ECONNRESET) => Outcome::Reset,
        Some(libc::EAGAIN) | Some(libc::ETIMEDOUT) | Some(libc::EPERM) => Outcome::Blocked,
        _ => match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => Outcome::Blocked,
            _ => Outcome::Error(e.to_string()),
        },
    }
}

fn tcp_connect(src: SocketAddr, dst: SocketAddr, mark: u32, ms: u64) -> Result<TcpStream, Outcome> {
    let dom = if dst.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: plain socket calls on a descriptor owned here with valid sockaddr pointers.
    unsafe {
        let fd = libc::socket(dom, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0);
        if fd < 0 {
            return Err(errno_outcome(&std::io::Error::last_os_error()));
        }
        let owned = OwnedFd::from_raw_fd(fd);
        let one: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&raw const one).cast(),
            4,
        );
        set_mark(fd, mark).map_err(Outcome::Error)?;
        let (s, sl) = sockaddr(src);
        if libc::bind(fd, (&raw const s).cast(), sl) != 0 {
            return Err(Outcome::Error(format!(
                "bind {src}: {}",
                std::io::Error::last_os_error()
            )));
        }
        let (d, dl) = sockaddr(dst);
        if libc::connect(fd, (&raw const d).cast(), dl) != 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(errno_outcome(&e));
            }
            let mut p = [libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            }];
            if poll1(&mut p, ms as i32) == 0 {
                return Err(Outcome::Blocked);
            }
            let mut err: libc::c_int = 0;
            let mut elen = 4 as libc::socklen_t;
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&raw mut err).cast(),
                &mut elen,
            );
            if err != 0 {
                return Err(errno_outcome(&std::io::Error::from_raw_os_error(err)));
            }
        }
        let fl = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, fl & !libc::O_NONBLOCK);
        Ok(TcpStream::from(owned))
    }
}

fn echo_roundtrip(s: &mut TcpStream, payload: &[u8], ms: u64) -> Outcome {
    s.set_read_timeout(Some(Duration::from_millis(ms))).unwrap();
    s.set_write_timeout(Some(Duration::from_millis(ms))).unwrap();
    if let Err(e) = s.write_all(payload) {
        return errno_outcome(&e);
    }
    let mut buf = vec![0u8; payload.len()];
    match s.read_exact(&mut buf) {
        Ok(()) if buf == payload => Outcome::Reply,
        Ok(()) => Outcome::Error("corrupt echo".into()),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Outcome::Reset,
        Err(e) => errno_outcome(&e),
    }
}

fn udp_roundtrip(src: SocketAddr, dst: SocketAddr, mark: u32, payload: &[u8], ms: u64) -> Outcome {
    let u = match UdpSocket::bind(src) {
        Ok(u) => u,
        Err(e) => return Outcome::Error(format!("bind {src}: {e}")),
    };
    if let Err(e) = set_mark(u.as_raw_fd(), mark) {
        return Outcome::Error(e);
    }
    if let Err(e) = u.connect(dst) {
        return Outcome::Error(format!("connect {dst}: {e}"));
    }
    u.set_read_timeout(Some(Duration::from_millis(ms))).unwrap();
    if let Err(e) = u.send(payload) {
        return errno_outcome(&e);
    }
    let mut buf = [0u8; 2048];
    match u.recv(&mut buf) {
        Ok(n) if &buf[..n] == payload => Outcome::Reply,
        Ok(_) => Outcome::Error("corrupt echo".into()),
        Err(e) => errno_outcome(&e),
    }
}

pub struct Obs {
    pub key: String,
    pub norm: String,
    pub raw: String,
}

pub struct WorldRun {
    pub front: Front,
    pub obs: Vec<Obs>,
    pub failures: Vec<String>,
    pub notes: Vec<String>,
    pub ns: [String; 3],
}

struct Run<'a> {
    w: &'a World,
    sinks: Sinks,
    held: HashMap<String, TcpStream>,
    last_counters: BTreeMap<String, u64>,
    snaps: HashMap<&'static str, String>,
    out: WorldRun,
    fault: Option<Fault>,
    reference: bool,
}

impl Run<'_> {
    fn expect(&mut self, ok: bool, msg: impl FnOnce() -> String) {
        if self.reference && !ok {
            let m = msg();
            self.out.failures.push(m);
        }
    }

    fn push(&mut self, key: String, norm: String, raw: String) {
        self.out.obs.push(Obs { key, norm, raw });
    }

    fn drain(&mut self) -> Vec<Seen> {
        self.sinks.rx.try_iter().collect()
    }

    fn policy_text(&self, p: &Ruleset) -> String {
        match (self.w.front, self.fault) {
            (Front::Nfcrt, Some(f)) => f.apply(&p.text),
            _ => p.text.clone(),
        }
    }

    fn apply_policy(&mut self, p: &Ruleset) -> (bool, String) {
        match self.w.front {
            Front::Typed => {
                let b = (p.typed.unwrap())(self.w.fam);
                let r = self.w.router.run(move || {
                    let mut s = Socket::new().map_err(|e| e.to_string())?;
                    s.commit(&b).map_err(|e| e.to_string())
                });
                match r {
                    Ok(_) => (true, String::new()),
                    Err(e) => (false, e),
                }
            }
            front => {
                let text = self.policy_text(p);
                let file = format!("{}.nft", p.label);
                std::fs::write(self.w.dir.join(&file), &text).unwrap();
                let bin = if front == Front::Nft { "nft" } else { nfcrt() };
                let o = exec(&self.w.router, bin, &["-f", &file], Some(&self.w.dir), None);
                (o.ok(), format!("{} {}{}", o.status(), o.stdout, o.stderr))
            }
        }
    }

    fn step(&mut self, st: &Step) -> Result<(), String> {
        match st {
            Step::Install(p) => {
                let (ok, raw) = self.apply_policy(p);
                self.expect(ok == p.ok, || {
                    format!("install {}: expected ok={}, got ok={ok}: {raw}", p.label, p.ok)
                });
                self.push(
                    format!("install {}", p.label),
                    if ok { "installed".into() } else { "rejected".into() },
                    raw,
                );
            }
            Step::Cli(c) => self.cli(c)?,
            Step::Probe(p) => self.probe(p)?,
            Step::Burst(b) => self.burst(b)?,
            Step::Send { name, want } => {
                let w = *want;
                let o = match self.held.get_mut(*name) {
                    Some(s) => echo_roundtrip(s, name.as_bytes(), if w { DELIVER_MS } else { SILENCE_MS }),
                    None => Outcome::Error("no such held connection".into()),
                };
                let seen = self.drain();
                self.expect((o == Outcome::Reply) == w && seen.is_empty(), || {
                    format!("send {name}: expected delivered={w}, got {}", o.name())
                });
                self.push(
                    format!("send {name}"),
                    format!("{} new-connections={}", o.name(), seen.len()),
                    o.name(),
                );
            }
            Step::Snap(s) => self.snap(s)?,
            Step::Replace(r) => self.replace(r)?,
            Step::Same(a, b) => {
                let (x, y) = (self.snaps.get(a).cloned(), self.snaps.get(b).cloned());
                if x != y || x.is_none() {
                    self.out.failures.push(format!(
                        "listing changed between {a} and {b}:\n--- {a}\n{}\n--- {b}\n{}",
                        x.unwrap_or_default(),
                        y.unwrap_or_default()
                    ));
                }
            }
        }
        Ok(())
    }

    fn cli(&mut self, c: &Cli) -> Result<(), String> {
        for (name, text) in &c.files {
            let p = self.w.dir.join(name);
            std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
            std::fs::write(p, text).map_err(|e| e.to_string())?;
        }
        let bin = match self.w.front {
            Front::Nft => "nft",
            Front::Nfcrt => nfcrt(),
            Front::Typed => return Err("CLI step in a typed world".into()),
        };
        let o = exec(&self.w.router, bin, &c.args, Some(&self.w.dir), c.stdin);
        let ok = o.ok();
        let crashed = o.signal.is_some() && c.reference_may_crash && self.w.front == Front::Nft;
        if crashed {
            self.out.notes.push(format!(
                "cli {}: reference nft died with {}; the candidate is judged by the fixture's expected status and unchanged policy",
                c.label,
                o.status()
            ));
        }
        self.expect(ok == c.ok, || {
            format!(
                "cli {}: expected ok={}, got {} stdout={:?} stderr={:?}",
                c.label,
                c.ok,
                o.status(),
                o.stdout,
                o.stderr
            )
        });
        let diag = if ok {
            String::new()
        } else if o.stderr.contains("Error:") || crashed {
            " diagnostic=error".to_string()
        } else {
            format!(" diagnostic=missing({})", o.status())
        };
        let out = if ok && c.stdout { mask_counters(&o.stdout) } else { String::new() };
        self.push(
            format!("cli {}", c.label),
            format!("ok={ok}{diag}\n{out}"),
            format!("{}\n--- stdout\n{}\n--- stderr\n{}", o.status(), o.stdout, o.stderr),
        );
        Ok(())
    }

    fn probe(&mut self, p: &Probe) -> Result<(), String> {
        let fam = self.w.fam;
        let (ns, src) = match p.from {
            Origin::Client(i) => (&self.w.client, SocketAddr::new(fam.client(i), p.sport)),
            Origin::Router => (&self.w.router, SocketAddr::new(fam.unspecified(), p.sport)),
        };
        let dst = SocketAddr::new(p.dst.0.addr(fam), p.dst.1);
        let ms = if p.want.delivered() { DELIVER_MS } else { SILENCE_MS };
        let payload = format!("{}:{}", p.name, p.sport).into_bytes();
        let (proto, mark, hold) = (p.proto, p.mark, p.hold);
        let (o, stream) = ns.run(move || match proto {
            Proto::Tcp => match tcp_connect(src, dst, mark, ms) {
                Ok(mut s) => {
                    let o = echo_roundtrip(&mut s, &payload, ms);
                    (o, Some(s))
                }
                Err(o) => (o, None),
            },
            Proto::Udp => (udp_roundtrip(src, dst, mark, &payload, ms), None),
        });
        if let Some(s) = stream {
            if hold && o == Outcome::Reply {
                self.held.insert(p.name.clone(), s);
            } else {
                self.held.insert(format!("~{}", p.name), s);
            }
        }
        let seen = self.drain();
        let key = format!("probe {}", p.name);
        let mut norm = o.name();
        let mut raw = o.name();
        for s in &seen {
            let port = match &p.want {
                Want::Delivered {
                    port: PeerPort::Range(lo, hi),
                    ..
                } => {
                    if (*lo..=*hi).contains(&s.peer.port()) {
                        format!("[{lo}-{hi}]")
                    } else {
                        s.peer.port().to_string()
                    }
                }
                _ => s.peer.port().to_string(),
            };
            let ip = match s.peer.ip() {
                IpAddr::V4(a) => a.to_string(),
                IpAddr::V6(a) => format!("[{a}]"),
            };
            let _ = write!(norm, "\n  at {} peer={ip}:{port} local={}", s.sink, s.local);
            let _ = write!(raw, "\n  at {} peer={} local={}", s.sink, s.peer, s.local);
        }
        let verdict = match &p.want {
            Want::Blocked => (o == Outcome::Blocked && seen.is_empty()).then_some(()),
            Want::Refused => (o == Outcome::Refused && seen.is_empty()).then_some(()),
            Want::Delivered { at, peer, port } => (o == Outcome::Reply
                && seen.len() == 1
                && &seen[0].sink == at
                && peer.is_none_or(|a| a == seen[0].peer.ip())
                && match port {
                    PeerPort::Same => peer.is_none() || seen[0].peer.port() == p.sport,
                    PeerPort::Exact(x) => seen[0].peer.port() == *x,
                    PeerPort::Range(lo, hi) => (*lo..=*hi).contains(&seen[0].peer.port()),
                })
            .then_some(()),
        };
        self.expect(verdict.is_some(), || {
            format!("probe {}: want {:?}, observed\n{raw}", p.name, p.want)
        });
        self.push(key, norm, raw);
        Ok(())
    }

    fn burst(&mut self, b: &Burst) -> Result<(), String> {
        let fam = self.w.fam;
        let ns = match b.from {
            Origin::Client(_) => &self.w.client,
            Origin::Router => &self.w.router,
        };
        let from = b.from;
        let dst = b.dst.addr(fam);
        let dgrams = b.dgrams.clone();
        let (fence_port, fence_src) = (b.fence_port, 39_999u16);
        let errors = ns.run(move || {
            pin_cpu();
            let mut dropped = 0usize;
            let mut send = |srcip: IpAddr, sport: u16, dport: u16, mark: u32, id: u32| {
                let u = UdpSocket::bind(SocketAddr::new(srcip, sport))
                    .map_err(|e| format!("bind {srcip}:{sport}: {e}"))?;
                set_mark(u.as_raw_fd(), mark)?;
                if u.send_to(&id.to_be_bytes(), SocketAddr::new(dst, dport)).is_err() {
                    dropped += 1;
                }
                Ok::<_, String>(())
            };
            for (id, d) in dgrams.iter().enumerate() {
                let srcip = match from {
                    Origin::Client(_) => fam.client(d.src),
                    Origin::Router => fam.unspecified(),
                };
                send(srcip, d.sport, d.dport, d.mark, id as u32)?;
            }
            let srcip = match from {
                Origin::Client(i) => fam.client(i),
                Origin::Router => fam.unspecified(),
            };
            send(srcip, fence_src, fence_port, 0, u32::MAX)?;
            Ok::<_, String>(dropped)
        })?;
        let deadline = Instant::now() + Duration::from_millis(FENCE_MS);
        let mut seen: Vec<Seen> = Vec::new();
        let mut fenced = false;
        while !fenced {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.sinks.rx.recv_timeout(left) {
                Ok(s) => {
                    fenced = s.sink == b.fence;
                    seen.push(s);
                }
                Err(_) => break,
            }
        }
        seen.extend(self.drain());
        if !fenced {
            self.out.failures.push(format!("burst {}: fence was never delivered", b.label));
        }
        let mut got: Vec<(u32, String)> = seen
            .iter()
            .filter(|s| s.sink != b.fence)
            .map(|s| (u32::from_be_bytes(s.payload[..4].try_into().unwrap()), s.sink.clone()))
            .collect();
        got.sort();
        let want: Vec<u32> = b
            .dgrams
            .iter()
            .enumerate()
            .filter(|(_, d)| d.want)
            .map(|(i, _)| i as u32)
            .collect();
        let got_ids: Vec<u32> = got.iter().map(|g| g.0).collect();
        self.expect(got_ids == want, || {
            format!(
                "burst {}: delivered datagrams {:?}, want {:?} (sender-side drops {errors})",
                b.label, got_ids, want
            )
        });
        let text = got.iter().map(|(i, s)| format!("{i}@{s}")).collect::<Vec<_>>().join(" ");
        self.push(
            format!("burst {}", b.label),
            format!("delivered {text}"),
            format!("sent={} sender-side-drops={errors} delivered {text}", b.dgrams.len()),
        );
        Ok(())
    }

    fn snap(&mut self, s: &SnapSpec) -> Result<(), String> {
        let listing = self.w.nft_list()?;
        let st = structural(&listing);
        let counters = counters_of(&listing);
        if self.w.front == Front::Nfcrt && s.lister {
            let ours = self.w.nfcrt_list()?;
            if self.fault.is_none() && st != structural(&ours) {
                self.out.failures.push(format!(
                    "snap {}: nfcrt list ruleset differs from nft list ruleset in the same namespace:\n{}",
                    s.label,
                    first_diff(&st, &structural(&ours))
                ));
            }
        }
        let mut norm = String::new();
        let mut raw = String::new();
        for (k, v) in &counters {
            let last = self.last_counters.get(k).copied().unwrap_or(0);
            let delta = if *v >= last { *v - last } else { *v };
            if k.starts_with('~') {
                let _ = writeln!(norm, "counter {k} delta={}", if delta > 0 { "nonzero" } else { "0" });
            } else {
                let _ = writeln!(norm, "counter {k} packets={v} delta={delta}");
            }
            let _ = writeln!(raw, "counter {k} packets={v} delta={delta}");
        }
        self.last_counters = counters.clone();
        for (k, want) in &s.counters {
            let got = counters.get(*k).copied();
            self.expect(got == Some(*want), || {
                format!("snap {}: counter {k} = {got:?}, want {want}", s.label)
            });
        }
        let mut ct = if s.conntrack { self.w.conntrack()? } else { Vec::new() };
        ct.retain(|l| !s.hide_ct.iter().any(|h| l.contains(h.as_str())));
        for (needles, lo, hi) in &s.nat_ports {
            for l in ct.iter_mut().filter(|l| needles.iter().all(|n| l.contains(n.as_str()))) {
                let Some(i) = l.rfind("dport=") else { continue };
                let digits: String = l[i + 6..].chars().take_while(|c| c.is_ascii_digit()).collect();
                if digits.parse::<u16>().is_ok_and(|p| (*lo..=*hi).contains(&p)) {
                    l.replace_range(i + 6..i + 6 + digits.len(), &format!("[{lo}-{hi}]"));
                }
            }
            ct.sort();
        }
        for l in &ct {
            let _ = writeln!(norm, "ct {l}");
            let _ = writeln!(raw, "ct {l}");
        }
        for needles in &s.tuples {
            let found = ct.iter().any(|l| needles.iter().all(|n| l.contains(n.as_str())));
            self.expect(found, || {
                format!("snap {}: no conntrack entry with {needles:?} in\n{}", s.label, ct.join("\n"))
            });
        }
        for needles in &s.absent {
            let found = ct.iter().any(|l| needles.iter().all(|n| l.contains(n.as_str())));
            self.expect(!found, || {
                format!("snap {}: unexpected conntrack entry with {needles:?} in\n{}", s.label, ct.join("\n"))
            });
        }
        let _ = writeln!(norm, "ruleset\n{st}");
        let _ = writeln!(raw, "ruleset\n{listing}");
        self.snaps.insert(s.label, st);
        self.push(format!("snap {}", s.label), norm, raw);
        Ok(())
    }

    fn replace(&mut self, r: &Replace) -> Result<(), String> {
        if self.w.front == Front::Typed {
            return Err("replace step in a typed world".into());
        }
        let fam = self.w.fam;
        let dst = SocketAddr::new(fam.server(0), r.canary_port);
        let sent = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (fence_port, fence_src) = (r.fence_port, SocketAddr::new(fam.client(0), 38_001));
        let fence_dst = SocketAddr::new(fam.server(0), fence_port);
        let client_ns = format!("/proc/self/task/{}/ns/net", self.w.client.tid);
        let src_ip = fam.client(0);
        let (ready_tx, ready_rx) = channel::<Result<(), String>>();
        let sender = {
            let (sent, stop) = (sent.clone(), stop.clone());
            std::thread::spawn(move || {
                let joined = std::fs::File::open(&client_ns)
                    .map_err(|e| format!("open {client_ns}: {e}"))
                    .and_then(|f| {
                        // SAFETY: setns on the calling thread with a namespace descriptor owned here.
                        if unsafe { libc::setns(f.as_raw_fd(), libc::CLONE_NEWNET) } == 0 {
                            Ok(())
                        } else {
                            Err(format!("setns: {}", std::io::Error::last_os_error()))
                        }
                    });
                let failed = joined.is_err();
                let _ = ready_tx.send(joined);
                if failed {
                    return;
                }
                pin_cpu();
                while !stop.load(Ordering::Relaxed) {
                    if let Ok(u) = UdpSocket::bind(SocketAddr::new(src_ip, 0)) {
                        let _ = u.send_to(b"canary", dst);
                    }
                    sent.fetch_add(1, Ordering::Relaxed);
                }
                if let Ok(u) = UdpSocket::bind(fence_src) {
                    let _ = u.send_to(b"fence", fence_dst);
                }
            })
        };
        if let Err(e) = ready_rx.recv().unwrap_or_else(|e| Err(e.to_string())) {
            let _ = sender.join();
            return Err(e);
        }
        let wait_for = |n: u64| -> bool {
            let end = Instant::now() + Duration::from_millis(DELIVER_MS);
            while sent.load(Ordering::Relaxed) < n {
                if Instant::now() > end {
                    return false;
                }
                std::thread::yield_now();
            }
            true
        };
        let ready = wait_for(200);
        let before = sent.load(Ordering::Relaxed);
        let pre: Vec<Seen> = self.drain();
        let pre_leak = pre.len();
        let split = self.fault == Some(Fault::SplitReplace) && self.w.front == Front::Nfcrt;
        let (ok, raw) = if split {
            let flush = Ruleset {
                label: "flush",
                text: "flush ruleset\n".into(),
                typed: None,
                ok: true,
            };
            let a = self.apply_policy(&flush);
            let mid = sent.load(Ordering::Relaxed);
            wait_for(mid + 200);
            let b = self.apply_policy(&r.policy);
            (a.0 && b.0, b.1)
        } else {
            self.apply_policy(&r.policy)
        };
        let after = sent.load(Ordering::Relaxed);
        let overlapped = wait_for(after + 200);
        stop.store(true, Ordering::Relaxed);
        sender.join().unwrap();
        let deadline = Instant::now() + Duration::from_millis(FENCE_MS);
        let mut seen: Vec<Seen> = Vec::new();
        let mut fenced = false;
        while !fenced {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.sinks.rx.recv_timeout(left) {
                Ok(s) => {
                    fenced = s.sink == r.fence;
                    seen.push(s);
                }
                Err(_) => break,
            }
        }
        seen.extend(self.drain());
        let leaked = seen.iter().filter(|s| s.sink == r.canary).count();
        let leaked = leaked + pre_leak;
        self.expect(ready && overlapped && after > before, || {
            format!(
                "replace {}: canary sender not running across the replacement (ready={ready}, before={before}, after={after})",
                r.policy.label
            )
        });
        self.expect(fenced, || "replace: fence was never delivered".into());
        self.expect(ok, || format!("replace {}: {raw}", r.policy.label));
        self.expect(leaked <= CANARY_BUDGET, || {
            format!(
                "replace {}: {leaked} canary packets delivered (budget {CANARY_BUDGET}), denied by both policies",
                r.policy.label
            )
        });
        self.push(
            format!("replace {}", r.policy.label),
            format!("installed={ok} canary-within-budget={}", leaked <= CANARY_BUDGET),
            format!("{raw}\ncanary sent before={before} after={after} delivered={leaked} (before replacement: {pre_leak})"),
        );
        Ok(())
    }
}

pub fn run_world(case: &Case, front: Front, fault: Option<Fault>, tag: &str) -> Result<WorldRun, String> {
    let dir = std::env::temp_dir().join(format!(
        "crab7-{}-{}-{}",
        std::process::id(),
        tag,
        front.name()
    ));
    let w = World::build(front, case.fam, dir)?;
    let sinks = start_sinks(&w, &case.sinks)?;
    let mut run = Run {
        w: &w,
        sinks,
        held: HashMap::new(),
        last_counters: BTreeMap::new(),
        snaps: HashMap::new(),
        out: WorldRun {
            front,
            obs: Vec::new(),
            failures: Vec::new(),
            notes: Vec::new(),
            ns: w.ns.clone(),
        },
        fault,
        reference: front == Front::Nft,
    };
    for st in &case.steps {
        run.step(st)?;
    }
    run.held.clear();
    Ok(run.out)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Passed,
    Failed,
    KnownDivergence,
    Skipped,
}

impl Status {
    pub fn name(self) -> &'static str {
        match self {
            Status::Passed => "passed",
            Status::Failed => "failed",
            Status::KnownDivergence => "known_divergence",
            Status::Skipped => "skipped",
        }
    }
}

pub struct CaseResult {
    pub id: String,
    pub row: &'static str,
    pub fam: Fam,
    pub status: Status,
    pub detail: Vec<String>,
    pub fronts: Vec<&'static str>,
    pub reference: Vec<(String, String)>,
    pub ms: u128,
    pub known: Option<&'static str>,
    pub generated: Option<(u64, usize)>,
    pub notes: Vec<String>,
}

pub fn skipped(case: &Case, why: &str) -> CaseResult {
    CaseResult {
        id: case.id.clone(),
        row: case.row,
        fam: case.fam,
        status: Status::Skipped,
        detail: vec![why.to_string()],
        fronts: Vec::new(),
        reference: Vec::new(),
        ms: 0,
        known: case.known,
        generated: case.generated,
        notes: Vec::new(),
    }
}

pub fn run_case(case: &Case, fault: Option<Fault>, tag: &str) -> CaseResult {
    let t0 = Instant::now();
    let mut fronts = vec![Front::Nft, Front::Nfcrt];
    if case.has_typed() {
        fronts.push(Front::Typed);
    }
    let mut runs: Vec<WorldRun> = Vec::new();
    let mut detail: Vec<String> = Vec::new();
    for f in &fronts {
        let (case2, tag2) = (case.clone(), tag.to_string());
        let (f2, fault2) = (*f, fault);
        let r = std::thread::spawn(move || run_world(&case2, f2, fault2, &tag2)).join();
        match r {
            Ok(Ok(w)) => runs.push(w),
            Ok(Err(e)) => detail.push(format!("{}: harness error: {e}", f.name())),
            Err(p) => {
                let m = p
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default();
                detail.push(format!("{}: panic: {m}", f.name()));
            }
        }
    }
    let mut reference = Vec::new();
    let mut divergences: Vec<String> = Vec::new();
    let mut failed = !detail.is_empty();
    if let Some(r) = runs.iter().find(|r| r.front == Front::Nft) {
        reference = r.obs.iter().map(|o| (o.key.clone(), o.raw.clone())).collect();
        for f in &r.failures {
            detail.push(format!("reference: {f}"));
            failed = true;
        }
        for c in runs.iter().filter(|c| c.front != Front::Nft) {
            for f in &c.failures {
                divergences.push(format!("{}: {f}", c.front.name()));
            }
            if c.obs.len() != r.obs.len() {
                divergences.push(format!(
                    "{}: {} observations, reference {}",
                    c.front.name(),
                    c.obs.len(),
                    r.obs.len()
                ));
            }
            for (a, b) in r.obs.iter().zip(&c.obs) {
                if a.norm != b.norm || a.key != b.key {
                    let mut d = format!(
                        "{}: {} differs\n  nft:\n{}\n  {}:\n{}",
                        c.front.name(),
                        a.key,
                        indent(&a.norm),
                        c.front.name(),
                        indent(&b.norm)
                    );
                    if a.key.starts_with("replace") || a.key.starts_with("cli") {
                        let _ = write!(d, "\n  raw nft:\n{}\n  raw {}:\n{}", indent(&a.raw), c.front.name(), indent(&b.raw));
                    }
                    divergences.push(d);
                }
            }
        }
    } else {
        failed = true;
    }
    let status = if failed {
        detail.extend(divergences);
        Status::Failed
    } else if divergences.is_empty() {
        if case.known.is_some() {
            detail.push("marked as a known divergence but it no longer reproduces: remove the marker".into());
            Status::Failed
        } else {
            Status::Passed
        }
    } else {
        detail.extend(divergences);
        if case.known.is_some() {
            Status::KnownDivergence
        } else {
            Status::Failed
        }
    };
    CaseResult {
        id: case.id.clone(),
        row: case.row,
        fam: case.fam,
        status,
        detail,
        fronts: fronts.iter().map(|f| f.name()).collect(),
        reference,
        ms: t0.elapsed().as_millis(),
        known: case.known,
        generated: case.generated,
        notes: runs.iter().flat_map(|r| r.notes.clone()).collect(),
    }
}

fn first_diff(a: &str, b: &str) -> String {
    let (x, y): (Vec<&str>, Vec<&str>) = (a.lines().collect(), b.lines().collect());
    for i in 0..x.len().max(y.len()) {
        let (l, r) = (x.get(i).copied().unwrap_or("<none>"), y.get(i).copied().unwrap_or("<none>"));
        if l != r {
            return format!("  line {i}:\n    nft:   {l}\n    nfcrt: {r}");
        }
    }
    String::new()
}

fn indent(s: &str) -> String {
    s.lines().map(|l| format!("    {l}")).collect::<Vec<_>>().join("\n")
}

pub fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn cmd_line(prog: &str, args: &[&str]) -> String {
    match Command::new(prog).args(args).output() {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            s.trim().to_string()
        }
        Err(e) => format!("unavailable: {e}"),
    }
}

fn which(prog: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join(prog))
            .find(|p| p.is_file())
    })
}

fn binary_identity(path: &Path) -> String {
    let sum = cmd_line("sha256sum", &[&path.to_string_lossy()]);
    let sum = sum.split_whitespace().next().unwrap_or("unavailable").to_string();
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    format!("{{\"path\":{},\"size\":{size},\"sha256\":{}}}", json_str(&path.to_string_lossy()), json_str(&sum))
}

pub fn profile_json() -> String {
    let rd = |p: &str| std::fs::read_to_string(p).unwrap_or_default().trim().to_string();
    let modules: Vec<String> = rd("/proc/modules")
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|m| m.starts_with("nf_") || m.starts_with("nft_") || m.starts_with("nfnetlink") || *m == "veth")
        .map(|m| m.to_string())
        .collect();
    let os = rd("/etc/os-release")
        .lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME=").map(|v| v.trim_matches('"').to_string()))
        .unwrap_or_default();
    let revision = std::env::var("QUALIFY_REVISION").unwrap_or_else(|_| {
        cmd_line("git", &["-c", "safe.directory=*", "rev-parse", "HEAD"])
    });
    let caps = rd("/proc/self/status")
        .lines()
        .find(|l| l.starts_with("CapEff"))
        .unwrap_or("")
        .to_string();
    let nft_bin = which("nft").map(|p| binary_identity(&p)).unwrap_or_else(|| "null".into());
    let ct_bin = which("conntrack").map(|p| binary_identity(&p)).unwrap_or_else(|| "null".into());
    let nfcrt_bin = binary_identity(Path::new(nfcrt()));
    let list = |v: &[&str]| v.iter().map(|s| json_str(s)).collect::<Vec<_>>().join(",");
    let mods = modules.iter().map(|s| json_str(s)).collect::<Vec<_>>().join(",");
    format!(
        concat!(
            "{{\"crabtables_revision\":{rev},\"nfcrt_version\":{nfv},\"build_profile\":{bp},",
            "\"qualify_features\":{feat},\"os\":{os},\"arch\":{arch},\"byte_order\":{bo},",
            "\"kernel_release\":{kr},\"kernel_version\":{kv},\"capabilities\":{caps},",
            "\"nft_version\":{nftv},\"conntrack_version\":{ctv},",
            "\"binaries\":{{\"nft\":{nftb},\"nfcrt\":{nfb},\"conntrack\":{ctb}}},",
            "\"kernel_modules\":[{mods}],",
            "\"scope\":{{\"families\":[{fams}],\"hooks\":[{hooks}],\"topology\":{topo},",
            "\"excluded\":[{excl}]}}}}"
        ),
        rev = json_str(&revision),
        nfv = json_str(&cmd_line(nfcrt(), &["--version"])),
        bp = json_str(if cfg!(debug_assertions) { "debug" } else { "release" }),
        feat = json_str(&std::env::var("QUALIFY_FEATURES").unwrap_or_else(|_| "unrecorded".into())),
        os = json_str(&os),
        arch = json_str(&cmd_line("uname", &["-m"])),
        bo = json_str(if cfg!(target_endian = "little") { "little" } else { "big" }),
        kr = json_str(&rd("/proc/sys/kernel/osrelease")),
        kv = json_str(&rd("/proc/sys/kernel/version")),
        caps = json_str(&caps),
        nftv = json_str(&cmd_line("nft", &["--version"])),
        ctv = json_str(&cmd_line("conntrack", &["--version"])),
        nftb = nft_bin,
        nfb = nfcrt_bin,
        ctb = ct_bin,
        mods = mods,
        fams = list(&["ip", "ip6", "inet"]),
        hooks = list(&["prerouting", "input", "forward", "output", "postrouting"]),
        topo = json_str("client - router(c0,s0) - server over veth, dual stack, netns per role, two worlds per scenario"),
        excl = list(&["bridge", "netdev", "flowtable offload", "NFQUEUE", "conntrack zones", "RELATED/INVALID stimuli"]),
    )
}

pub fn evidence_json(
    results: &[CaseResult],
    required: &[(&str, Fam)],
    seeds: &[(&str, u64)],
    complete: bool,
) -> (String, bool, Vec<String>) {
    let count = |s: Status| results.iter().filter(|r| r.status == s).count();
    let mut missing: Vec<String> = Vec::new();
    for (row, fam) in required {
        let rows: Vec<&CaseResult> = results
            .iter()
            .filter(|r| r.row == *row && r.fam == *fam)
            .collect();
        if rows.is_empty() {
            missing.push(format!("{row}/{}: no case", fam.tag()));
        } else {
            for bad in rows.iter().filter(|r| r.status != Status::Passed) {
                missing.push(format!("{row}/{}: {} is {}", fam.tag(), bad.id, bad.status.name()));
            }
        }
    }
    let qualified = complete && missing.is_empty();
    let mut s = String::new();
    let _ = write!(s, "{{\"schema\":1,\"suite\":\"CRAB-7\",\"profile\":{},", profile_json());
    let _ = write!(
        s,
        "\"seeds\":{{{}}},",
        seeds
            .iter()
            .map(|(k, v)| format!("{}:{v}", json_str(k)))
            .collect::<Vec<_>>()
            .join(",")
    );
    let _ = write!(
        s,
        "\"summary\":{{\"inventory\":{},\"executed\":{},\"passed\":{},\"failed\":{},\"known_divergence\":{},\"skipped\":{},\"complete\":{complete},\"qualified\":{qualified},\"unmet_required_rows\":[{}]}},",
        results.len(),
        results.len() - count(Status::Skipped),
        count(Status::Passed),
        count(Status::Failed),
        count(Status::KnownDivergence),
        count(Status::Skipped),
        missing.iter().map(|m| json_str(m)).collect::<Vec<_>>().join(",")
    );
    s.push_str("\"cases\":[");
    for (i, r) in results.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let obs = r
            .reference
            .iter()
            .map(|(k, v)| format!("{{\"step\":{},\"reference\":{}}}", json_str(k), json_str(v)))
            .collect::<Vec<_>>()
            .join(",");
        let notes = r.notes.iter().map(|n| json_str(n)).collect::<Vec<_>>().join(",");
        let generated = r
            .generated
            .map(|(seed, n)| format!("{{\"seed\":{seed},\"cases\":{n}}}"))
            .unwrap_or_else(|| "null".into());
        let _ = write!(
            s,
            "{{\"id\":{},\"row\":{},\"family\":{},\"frontends\":[{}],\"status\":{},\"known_divergence\":{},\"generated\":{generated},\"elapsed_ms\":{},\"detail\":{},\"notes\":[{notes}],\"reference_observations\":[{obs}]}}",
            json_str(&r.id),
            json_str(r.row),
            json_str(r.fam.tag()),
            r.fronts.iter().map(|f| json_str(f)).collect::<Vec<_>>().join(","),
            json_str(r.status.name()),
            r.known.map(json_str).unwrap_or_else(|| "null".into()),
            r.ms,
            json_str(&r.detail.join("\n"))
        );
    }
    s.push_str("]}");
    (s, qualified, missing)
}
