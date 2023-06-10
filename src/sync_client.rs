//! Synchronous Gree cilent
//! 
//! * `GreeClient` is a low-level API
//! * `Gree` is a high-level Gree protocol client


use std::{net::{Ipv4Addr, UdpSocket, SocketAddr, IpAddr}, time::{Duration, Instant}, sync::mpsc::{Sender, Receiver}};
use serde_json::Value;

use crate::{state::*, vars::VarName};

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
    c: GreeClient,
    s: GreeState,
    cfg: GreeConfig,
    scan_ts: Option<Instant>,
}

impl GreeInternal {
    pub fn new(cfg: GreeConfig) -> Result<Self> { 
        Ok(Self { 
            c: GreeClient::new()?,
            s: GreeState::new(),
            cfg,
            scan_ts: None,
        })
    }

    fn scan(&mut self, forced: bool) -> Result<()> {
        let now = Instant::now();

        let allow = match self.scan_ts {
            None => true,
            Some(w) if now >= w + self.cfg.max_scan_age => true,
            Some(w) if now >= w + self.cfg.min_scan_age && forced => true,
            _ => false
        };
        if allow {
            let result = self.c.scan(self.cfg.bcast_addr, self.cfg.max_count)?;
            self.scan_ts = Some(Instant::now());
            self.s.scan_ind(result);
        } 
        Ok(())
    }


    fn bindc(mac: &MacAddr, dev: &mut Device, c: &GreeClient) -> Result<()> {
        if dev.key.is_none() {
            let pack = c.bind(dev.ip, mac)?;
            dev.bind_ind(pack);
        }
        Ok(())
    }



    fn net_read<T: NetVar>(mac: &MacAddr, dev: &Device, c: &GreeClient, vars: &mut NetVarBag<T>) -> Result<()> {
        let key = dev.key.as_ref().ok_or_else(|| Error::mac_not_bound(mac))?;
        let names: Vec<VarName> = vars
            .iter()
            .filter_map(|(name, nv)| if nv.is_net_read_pending() { Some(*name) } else { None })
            .collect();
        if names.is_empty() { return Ok(()) }
        let pack = c.status(dev.ip, mac, key, &names)?;
        for (n, v) in pack.cols.into_iter().zip(pack.dat.into_iter()) { 
            if let Some(nv) = vars::name_of(&n).and_then(|n| vars.get_mut(n)) {
                nv.net_set(v);
            }
        }
        Ok(())
    }

    fn net_write<T: NetVar>(mac: &MacAddr, dev: &Device, c: &GreeClient, vars: &mut NetVarBag<T>) -> Result<()> {
        let key = dev.key.as_ref().ok_or_else(|| Error::mac_not_bound(mac))?;

        let mut names = vec![];
        let mut values = vec![];
        for (n, nv) in vars.iter() {
            if nv.is_net_write_pending() {
                names.push(*n);
                values.push(nv.net_get().clone());
            }
        }
        if names.is_empty() { return Ok(()) }
        let pack = c.setvars(dev.ip, mac, key, &names, &values)?;
        for (n, v) in pack.opt.into_iter().zip(pack.p.into_iter()) {
            if let Some(nv) = vars::name_of(&n).and_then(|n| vars.get_mut(&n)) {
                nv.clear_net_write_pending();
                nv.net_set(v);
            }
        }
        Ok(())
    }


    fn apply_dev<T: NetVar>(mac: &MacAddr, dev: &mut Device, c: &GreeClient, op: &mut Op<'_, T>) -> Result<()> {
        Self::bindc(mac, dev, c)?;
        match op {
            Op::Bind => Ok(()),
            Op::NetRead(vars) => Self::net_read(mac, dev, c, *vars),
            Op::NetWrite(vars) => Self::net_write(mac, dev, c, *vars)
        }
    }

    fn apply<T: NetVar>(&mut self, target: &String, op: &mut Op<'_, T>) -> Result<()> {
        let mac = self.cfg.aliases.get(target).unwrap_or(target);
        let dev = self.s.devices.get_mut(mac).ok_or_else(|| Error::not_found(target))?;
        Self::apply_dev(mac, dev, &self.c, op)
    }

    /// applies Op to target; retries after forced scan on failure
    fn apply_retrying<T: NetVar>(&mut self, target: &String, mut op: Op<'_, T>) -> Result<()> {
        let () = self.scan(false)?;
        let r = self.apply(target, &mut op);
        if r.is_ok() { return Ok(());}
        let () = self.scan(true)?;        
        self.apply(target, &mut op)
    }
}

pub struct Gree {
    g: GreeInternal,
}

impl Gree {

    pub fn new() -> Result<Self> {
        Ok(Self { g: GreeInternal::new(Default::default())? })
    }

    pub fn from_config(cfg: GreeConfig) -> Result<Self> { 
        Ok(Self { g: GreeInternal::new(cfg)? })
    }

    pub fn state(&self) -> &GreeState { &self.g.s }

    /// Performs scan and fills state
    pub fn scan(&mut self) -> Result<()> { 
        self.g.scan(false) 
    }

    /// Binds 
    pub fn bind(&mut self, target: &String) -> Result<()> { 
        self.g.apply_retrying(target, Op::<SimpleNetVar>::Bind) 
    }

    /// Reads pending variables from the network
    pub fn net_read<T: NetVar>(&mut self, target: &String, vars: &mut NetVarBag<T>) -> Result<()> { 
        self.g.apply_retrying(target, Op::NetRead(vars)) 
    }

    /// Writes pending variables to the network
    pub fn net_write<T: NetVar>(&mut self, target: &String, vars: &mut NetVarBag<T>)  -> Result<()> {
        self.g.apply_retrying(target, Op::NetWrite(vars))
    }

}

