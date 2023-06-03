//! Synchronous Gree cilent
//! 
//! * `GreeClient` is a low-level API
//! * `Gree` is a high-level Gree protocol client


use std::{net::{Ipv4Addr, UdpSocket, SocketAddr, IpAddr}, time::{Duration, SystemTime, Instant}, sync::mpsc::{Sender, Receiver}};
use serde_json::Value;

use crate::tree::{MacAddr, Device};

use super::*;


/// Low-level Gree API
/// 
/// Uses background thread to read values from the network.
pub struct GreeClient {
    s: UdpSocket,
    r: Receiver<(SocketAddr, GenericMessage)>,
    recv_timeout: Duration
}

impl GreeClient {
    fn recv_loop(s: UdpSocket, send: Sender<(SocketAddr, GenericMessage)>) -> Result<()> {
        let mut b = [0u8; 2048];
        loop {
            let (len, addr) = s.recv_from(&mut b)?;
            trace!("[{}] raw: {}", addr, String::from_utf8_lossy(&b[..len]));
            let p: GenericMessage = serde_json::from_slice(&b[..len])?;
            debug!("[{}]: {:?}", addr, p);
            send.send((addr, p))?;
        }
    }

    fn exchange<'t>(&self, ip: IpAddr, request: &GenericOutMessage<'t>) -> Result<GenericMessage> {
        let b = serde_json::to_vec(request)?;
        self.s.send_to(&b, (ip, PORT))?;
        loop {
            let (ra, gm) = self.r.recv_timeout(self.recv_timeout)?;
            if ra.ip() == ip { break Ok(gm) }
        }
    }

    /// Creates new client
    pub fn new() -> Result<Self> {
        let sa: SocketAddr = (Ipv4Addr::UNSPECIFIED, PORT + 1).into();
        let s = UdpSocket::bind(sa)?;
        let sr = s.try_clone()?;
        let (send, r) = std::sync::mpsc::channel();
        std::thread::spawn(|| if let Err(e) = Self::recv_loop(sr, send) { error!("Recv: {e}") });
        let recv_timeout = Duration::from_secs(3);
        Ok(Self { s, r, recv_timeout })
    }

    pub fn scan(&self, bcast_addr: IpAddr, max_count: usize) -> Result<Vec<(IpAddr, GenericMessage, ScanResponsePack)>> {
        self.s.send_to(scan_request(), (bcast_addr, PORT))?;
    
        let mut rv = vec![];
    
        for _ in 0..max_count {
            match self.r.recv_timeout(self.recv_timeout) {
                Ok((addr, gm)) => {
                    let pack = handle_response(addr.ip(), &gm.pack, GENERIC_KEY)?;
                    rv.push((addr.ip(), gm, pack));
                } 
                Err(_) => break, //timeout
            }
        }
        Ok(rv)
    }
    
    pub fn bind(&self, addr: IpAddr, mac: &str) -> Result<BindResponsePack> {
        let gm = bind_request(mac, GENERIC_KEY)?;
        let ogm = self.exchange(addr, &gm)?;
        Ok(handle_response(addr, &ogm.pack, GENERIC_KEY)?)
    }

    pub fn status(&self, addr: IpAddr, mac: &str, key: &str, vars: &[&str]) -> Result<StatusResponsePack> {
        let gm = status_request(mac, key, vars)?;
        let ogm = self.exchange(addr, &gm)?;
        Ok(handle_response(addr, &ogm.pack, key)?)
    }

    pub fn setvars(&self, addr: IpAddr, mac: &str, key: &str, names: &[&'static str], values: &[Value]) -> Result<CommandResponsePack> {
        let gm = setvar_request(mac, key, names, values)?;
        let ogm = self.exchange(addr, &gm)?;
        Ok(handle_response(addr, &ogm.pack, key)?)
    }

}


struct GreeInternal {
    t: Tree,
    c: GreeClient,
    discovery_instant: Option<Instant>,
    max_count: usize,
    bcast_addr: IpAddr,
    min_discovery_age: Duration,
    max_discovery_age: Duration,
}

impl GreeInternal {
    pub const DEFAULT_MAX_COUNT: usize = 10;
    pub const DEFAULT_BROADCAST_ADDR: [u8; 4] =  [10, 0, 0, 255];
    pub const DEFAULT_MIN_DISCOVERY_AGE: Duration = Duration::from_secs(60);
    pub const DEFAULT_MAX_DISCOVERY_AGE: Duration = Duration::from_secs(3600 * 24);

    pub fn new() -> Result<Self> { 
        Ok(Self { 
            t: Tree::new(SystemTime::now()), 
            c: GreeClient::new()?,
            discovery_instant: None,
            max_count: Self::DEFAULT_MAX_COUNT , 
            bcast_addr: Self::DEFAULT_BROADCAST_ADDR.into(),
            min_discovery_age: Self::DEFAULT_MIN_DISCOVERY_AGE,
            max_discovery_age: Self::DEFAULT_MAX_DISCOVERY_AGE,
        })
    }

    fn bindc(mac: &MacAddr, dev: &mut Device, c: &GreeClient) -> Result<()> {
        if dev.key.is_none() {
            let pack = c.bind(dev.ip, mac)?;
            dev.bind_ind(SystemTime::now(), pack);
        }
        Ok(())
    }

    fn apply(&mut self, scope: Option<&MacAddr>, mut f: impl FnMut(&MacAddr, &mut Device, &GreeClient) -> Result<()>) -> Result<()> {
        let mut fbound = |mac: &MacAddr, dev: &mut Device, c: &GreeClient| -> Result<()> {
            Self::bindc(mac, dev, c)?;
            f(mac, dev,c)
        };
        match scope {
            None => {
                for (mac, dev) in self.t.devices.iter_mut() { 
                    if let Err(e) = fbound(mac, dev, &self.c) {
                        error!("device@{mac}: {e}")
                    }
                }
                Ok(())
            }
            Some(mac) => {
                let dev = self.t.devices
                    .get_mut(mac)
                    .ok_or_else(||->Error { format!("mac {mac} not found").into()})?;
                fbound(mac, dev, &self.c)
            }       
        }
    }

    fn discover(&mut self, force: bool) -> Result<bool> {
        let now = Instant::now();
        let allow = match self.discovery_instant {
            None => true,
            Some(w) if now >= w + self.max_discovery_age => true,
            Some(w) if now >= w + self.min_discovery_age && force => true,
            _ => false
        };
        if allow {
            let sr = self.c.scan(self.bcast_addr, self.max_count)?;
            self.t.scan_ind(SystemTime::now(), sr);
            self.discovery_instant = Some(Instant::now());
        }
        Ok(allow)
    }

    fn op(&mut self, scope: Option<&MacAddr>, mut f: impl FnMut(&MacAddr, &mut Device, &GreeClient) -> Result<()>) -> Result<()> {
        let _ = self.discover(false)?;
        match self.apply(scope, &mut f) {
            Ok(()) => Ok(()),
            Err(e) => {
                if let Ok(true) = self.discover(true) {
                    self.apply(scope, f)
                } else {
                    Err(e)
                }
            }
        }
    }

}

pub struct Gree {
    gt: GreeInternal,
}

impl Gree {

    pub fn new() -> Result<Self> { 
        Ok(Self { gt: GreeInternal::new()? })
    }

    pub fn tree(&self) -> &Tree { &self.gt.t }

    fn status(mac: &MacAddr, dev: &mut Device, c: &GreeClient, vars: &[&str]) -> Result<()> {
        let key = dev.key.as_ref().ok_or_else(|| format!("{mac} not bound"))?;
        let pack = c.status(dev.ip, mac, key, vars)?;
        dev.status_ind(SystemTime::now(), pack.cols, pack.dat);
        Ok(())
    }

    fn setvars(mac: &MacAddr, dev: &mut Device, c: &GreeClient, vars: &[&'static str], vals: &[Value]) -> Result<()> {
        let key = dev.key.as_ref().ok_or_else(|| format!("{mac} not bound"))?;
        let pack = c.setvars(dev.ip, mac, key, vars, vals)?;
        dev.status_ind(SystemTime::now(), pack.opt, pack.p);
        Ok(())
    }

    /// Reads variables from the network
    pub fn sync(&mut self, scope: Option<&MacAddr>, vars: &[&'static str]) {
        self.sync_and_visit(scope, vars, |_,_|())
    }

    /// For each device in scope, reads vars from the network and calls visitor
    pub fn sync_and_visit(&mut self, scope: Option<&MacAddr>, vars: &[&'static str], mut visitor: impl FnMut(&MacAddr, &Device)) {
        let r = self.gt.op(scope, |mac: &MacAddr, dev: &mut Device, c: &GreeClient| -> Result<()> {
            Self::status(mac, dev, c, vars)?;
            visitor(mac, dev);
            Ok(())
        });
        if let Err(e) = r {
            error!("sync: {e}")
        }
    }

    pub fn set(&mut self, scope: Option<&MacAddr>, vars: &[&'static str], vals: &[Value]) {
        let r = self.gt.op(scope, |mac: &MacAddr, dev: &mut Device, c: &GreeClient| -> Result<()> {
            Self::setvars(mac, dev, c, vars, vals)
        });
        if let Err(e) = r {
            error!("update: {e}")
        }
    }


}

