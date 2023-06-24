//! Synchronous Gree cilents
//! 
//! * `GreeClient` is a low-level API
//! * `Gree` is a high-level Gree protocol client
//! 
//! Example usage:
//! 
//! ```
//! let mut cc = GreeClientConfig::default();
//! cc.bcast_addr = [192, 168, 0, 255].into();
//! let c = GreeClient::new(cc)?;
//! for (ip, _, pack) in  cc.scan()? {
//!     println!("{ip} {pack:?}")
//! }
//! ```

use std::{net::{UdpSocket, SocketAddr, IpAddr}, time::Instant, sync::mpsc::{Sender, Receiver, TryRecvError}};
use serde_json::Value;
use crate::{state::*, vars::VarName};
use super::*;


/// Low-level Gree API
/// 
/// Uses background thread to read values from the network.
/// 
/// See module-level docs for a quick example.
pub struct GreeClient {
    s: UdpSocket,
    r: Receiver<(SocketAddr, GenericMessage)>,
    cfg: GreeClientConfig,
}

impl GreeClient {
    fn recv_loop(s: UdpSocket, send: Sender<(SocketAddr, GenericMessage)>, buffer_size: usize) -> Result<()> {
        trace!("recv_loop: buffer_size={buffer_size}");
        let mut b = vec![0u8; buffer_size];
        loop {
            let (len, addr) = s.recv_from(&mut b)?;
            trace!("[{}] raw: {}", addr, String::from_utf8_lossy(&b[..len]));
            let p: GenericMessage = serde_json::from_slice(&b[..len])?;
            debug!("[{}]: {:?}", addr, p);
            send.send((addr, p))?;
        }
    }

    fn exchange<'t>(&self, ip: IpAddr, request: &GenericOutMessage<'t>) -> Result<GenericMessage> {
        //Drain the receiver queue
        loop {
            match self.r.try_recv() {
                Ok(_) => (),
                Err(TryRecvError::Empty) => break Ok(()),
                Err(TryRecvError::Disconnected) => break Err(Error::receiver_disconnected()),
            }
        }?;
        let b = serde_json::to_vec(request)?;
        let nbytes = self.s.send_to(&b, (ip, PORT))?;
        if nbytes != b.len() {
            error!("sent {}, expected {}", nbytes, b.len());
        }
        loop {
            let (ra, gm) = self.r.recv_timeout(self.cfg.recv_timeout)?;
            if ra.ip() == ip { break Ok(gm) }
        }
    }

    /// Creates new client
    pub fn new(cfg: GreeClientConfig) -> Result<Self> {
        let s = UdpSocket::bind(cfg.bind_addr)?;
        trace!("Bound to: {:?}", s.local_addr());
        s.set_broadcast(true)?;
        let sr = s.try_clone()?;
        let (send, r) = std::sync::mpsc::channel();
        std::thread::spawn(move || if let Err(e) = Self::recv_loop(sr, send, cfg.buffer_size) { error!("Recv: {e}") });
        Ok(Self { s, r, cfg })
    }

    /// Performs network scan to discover devices. 
    /// 
    /// The scan is terminated either when max device count is reached, or by timeout  
    pub fn scan(&self) -> Result<Vec<(IpAddr, GenericMessage, ScanResponsePack)>> {
        self.s.send_to(scan_request(), (self.cfg.bcast_addr, PORT))?;
    
        let mut rv = vec![];
    
        for _ in 0..self.cfg.max_count {
            match self.r.recv_timeout(self.cfg.recv_timeout) {
                Ok((addr, gm)) => {
                    let pack = handle_response(addr.ip(), &gm.pack, GENERIC_KEY)?;
                    rv.push((addr.ip(), gm, pack));
                } 
                Err(_) => break, //timeout
            }
        }
        Ok(rv)
    }
    
    /// Performs binding operation on a device
    pub fn bind(&self, addr: IpAddr, mac: &str) -> Result<BindResponsePack> {
        let gm = bind_request(mac, GENERIC_KEY)?;
        let ogm = self.exchange(addr, &gm)?;
        Ok(handle_response(addr, &ogm.pack, GENERIC_KEY)?)
    }

    /// Reads specified variables from the device
    pub fn getvars(&self, addr: IpAddr, mac: &str, key: &str, vars: &[&str]) -> Result<StatusResponsePack> {
        let gm = status_request(mac, key, vars)?;
        let ogm = self.exchange(addr, &gm)?;
        Ok(handle_response(addr, &ogm.pack, key)?)
    }

    /// Writes specified variables to the device
    pub fn setvars(&self, addr: IpAddr, mac: &str, key: &str, names: &[VarName], values: &[Value]) -> Result<CommandResponsePack> {
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
            c: GreeClient::new(cfg.client_config)?,
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
            let result = self.c.scan()?;
            self.scan_ts = Some(Instant::now());
            self.s.scan_ind(result);
        } 
        Ok(())
    }

    fn bindc(mac: &str, dev: &mut Device, c: &GreeClient) -> Result<()> {
        if dev.key.is_none() {
            let pack = c.bind(dev.ip, mac.as_ref())?;
            dev.bind_ind(pack);
        }
        Ok(())
    }

    fn net_read<T: NetVar>(mac: &str, dev: &Device, c: &GreeClient, vars: &mut NetVarBag<T>) -> Result<()> {
        let key = dev.key.as_ref().ok_or_else(|| Error::mac_not_bound(mac))?;
        let names: Vec<VarName> = vars
            .iter()
            .filter_map(|(name, nv)| if nv.is_net_read_pending() { Some(*name) } else { None })
            .collect();
        if names.is_empty() { return Ok(()) }
        let pack = c.getvars(dev.ip, mac, key, &names)?;
        for (n, v) in pack.cols.into_iter().zip(pack.dat.into_iter()) { 
            if let Some(nv) = vars::name_of(&n).and_then(|n| vars.get_mut(n)) {
                nv.net_set(v);
            }
        }
        Ok(())
    }

    fn net_write<T: NetVar>(mac: &str, dev: &Device, c: &GreeClient, vars: &mut NetVarBag<T>) -> Result<()> {
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


    fn apply_dev<T: NetVar>(mac: &str, dev: &mut Device, c: &GreeClient, op: &mut Op<'_, T>) -> Result<()> {
        Self::bindc(mac, dev, c)?;
        match op {
            Op::Bind => Ok(()),
            Op::NetRead(vars) => Self::net_read(mac, dev, c, *vars),
            Op::NetWrite(vars) => Self::net_write(mac, dev, c, *vars)
        }
    }

    fn apply<T: NetVar>(&mut self, target: &str, op: &mut Op<'_, T>) -> Result<()> {
        let mac = self.cfg.aliases.get(target).map(|s| s.as_str()).unwrap_or(target);
        let dev = self.s.devices.get_mut(mac).ok_or_else(|| Error::not_found(target.as_ref()))?;
        Self::apply_dev(mac, dev, &self.c, op)
    }

    /// applies Op to target; retries after forced scan on failure
    fn apply_retrying<T: NetVar>(&mut self, target: &str, mut op: Op<'_, T>) -> Result<()> {
        let () = self.scan(false)?;
        let r = self.apply(target, &mut op);
        if r.is_ok() { return Ok(());}
        let () = self.scan(true)?;        
        self.apply(target, &mut op)
    }

    fn with_device<R>(&self, target: &str, f: impl FnOnce(&Device) -> R) -> Result<R> {
        let mac = self.cfg.aliases.get(target).map(|s| s.as_str()).unwrap_or(target);
        let dev = self.s.devices.get(mac).ok_or_else(||Error::not_found(target))?;
        Ok(f(dev))    
    }

    /// applies f to the target's state; retries after forced scan on failure (i.e. if device not found)
    fn with_device_retrying<R>(&mut self, target: &str, f: impl Fn(&Device) -> R) -> Result<R> {
        let () = self.scan(false)?;
        let r = self.with_device(target, &f);
        if r.is_ok() { return r }
        let () = self.scan(true)?;        
        self.with_device(target, &f)
    }


}


/// High-level Gree client
/// 
/// It maintains consistent network state through periodically re-scanning the network. See the crate level documentation 
/// for the explanation of the re-scanning rules.
pub struct Gree {
    g: GreeInternal,
}

impl Gree {
    /// Creates a new Gree client from configuration
    pub fn new(cfg: GreeConfig) -> Result<Self> { 
        Ok(Self { g: GreeInternal::new(cfg)? })
    }

    /// Calls `f` with the current state
    pub fn with_state<R>(&mut self, f: impl Fn(&GreeState) -> R) -> Result<R> {
        self.g.scan(false)?;
        Ok(f(&self.g.s))
    }

    /// Calls `f` with the device specified as `target`
    /// 
    /// Performs forced scan if the device was not found.
    pub fn with_device<R>(&mut self, target: &String, f: impl Fn(&Device) -> R) -> Result<R> {
        self.g.with_device_retrying(target, f)
    }

    /// Reads pending variables from the network
    pub fn net_read<T: NetVar>(&mut self, target: &str, vars: &mut NetVarBag<T>) -> Result<()> { 
        self.g.apply_retrying(target, Op::NetRead(vars)) 
    }

    /// Writes pending variables to the network, and fills the netvar bag with the values returned from the network 
    pub fn net_write<T: NetVar>(&mut self, target: &str, vars: &mut NetVarBag<T>)  -> Result<()> {
        self.g.apply_retrying(target, Op::NetWrite(vars))
    }

    /// Executes the operation specified
    pub fn execute<T: NetVar>(&mut self, target: &str, op: Op<'_, T>)  -> Result<()> {
        self.g.apply_retrying(target, op)
    }

    /// Performs explicit scan
    pub fn scan(&mut self) -> Result<()> { 
        self.g.scan(true) 
    }

    /// Performs explicit bind
    /// 
    /// Note that this method is rarely needed, as binds are usually performed under-the-hood when necessary.
    pub fn bind(&mut self, target: &str) -> Result<()> { 
        self.g.apply_retrying(target, Op::<SimpleNetVar>::Bind) 
    }
}

