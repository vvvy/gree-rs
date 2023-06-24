//! Asynchronous Gree cilents (requires `tokio`)
//! 
//! Example usage:
//! 
//! ```
//! let mut cc = GreeClientConfig::default();
//! cc.bcast_addr = [192, 168, 0, 255].into();
//! let c = GreeClient::new(cc).await?;
//! for (ip, _, pack) in  cc.scan().await? {
//!     println!("{ip} {pack:?}")
//! }
//! ```

#![cfg(feature = "tokio")]

use std::{net::IpAddr, time::Instant};
use tokio::{select, net::UdpSocket, time};
use serde_json::Value;
use crate::{state::*, vars::VarName};
use super::*;

/// Low-level Gree API
/// 
/// See module-level docs for a quick example.
pub struct GreeClient {
    s: UdpSocket,
    cfg: GreeClientConfig,
}

impl GreeClient {
    /// Crates new `GreeClient` from `GreeClientConfig`
    pub async fn new(cfg: GreeClientConfig) -> Result<Self> {
        let s = UdpSocket::bind(cfg.bind_addr).await?;
        s.set_broadcast(true)?;
        trace!("Bound to: {:?}", s.local_addr());
        Ok(Self { s, cfg })
    }

    async fn recv(&self) -> Result<(IpAddr, GenericMessage)> {
        let mut b = vec![0u8; self.cfg.buffer_size];
        let (len, addr) = select! {
            la = self.s.recv_from(&mut b) => { la? }
            _ = time::sleep(self.cfg.recv_timeout) => { Err(Error::ResponseTimeout)? }
        };

        trace!("[{}] raw: {}", addr, String::from_utf8_lossy(&b[..len]));

        let gm: GenericMessage = serde_json::from_slice(&b[..len])?;
        debug!("[{}]: {:?}", addr, gm);

        Ok((addr.ip(), gm))
    }

    async fn exchange<'t>(&self, ip: IpAddr, request: &GenericOutMessage<'t>) -> Result<GenericMessage> {
        let b = serde_json::to_vec(request)?;
        self.s.send_to(&b, (ip, PORT)).await?;

        let gm = loop {
            let (addr, gm) = self.recv().await?;
            if addr == ip { break gm }
        };

        Ok(gm)
    }

    /// Performs network scan to discover devices. 
    /// 
    /// The scan is terminated either when max device count is reached, or by timeout     
    pub async fn scan(&self) -> Result<Vec<(IpAddr, GenericMessage, ScanResponsePack)>> {
        self.s.send_to(scan_request(), (self.cfg.bcast_addr, PORT)).await?;
    
        let mut rv = vec![];
    
        for _ in 0..self.cfg.max_count {
            match self.recv().await {
                Ok((addr, gm)) => {
                    let pack = handle_response(addr, &gm.pack, GENERIC_KEY)?;
                    rv.push((addr, gm, pack));
                } 
                Err(_) => break, //timeout
            }
        }
        Ok(rv)
    }
    
    /// Performs binding operation on a device
    pub async fn bind(&self, addr: IpAddr, mac: &str) -> Result<BindResponsePack> {
        let gm = bind_request(mac, GENERIC_KEY)?;
        let ogm = self.exchange(addr, &gm).await?;
        Ok(handle_response(addr, &ogm.pack, GENERIC_KEY)?)
    }

    /// Reads specified variables from the device
    pub async fn getvars(&self, addr: IpAddr, mac: &str, key: &str, vars: &[&str]) -> Result<StatusResponsePack> {
        let gm = status_request(mac, key, vars)?;
        let ogm = self.exchange(addr, &gm).await?;
        Ok(handle_response(addr, &ogm.pack, key)?)
    }

    /// Writes specified variables to the device
    pub async fn setvars(&self, addr: IpAddr, mac: &str, key: &str, names: &[VarName], values: &[Value]) -> Result<CommandResponsePack> {
        let gm = setvar_request(mac, key, names, values)?;
        let ogm = self.exchange(addr, &gm).await?;
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
    pub async fn new(cfg: GreeConfig) -> Result<Self> { 
        Ok(Self { 
            c: GreeClient::new(cfg.client_config).await?,
            s: GreeState::new(),
            cfg,
            scan_ts: None,
        })
    }

    async fn scan(&mut self, forced: bool) -> Result<()> {
        let now = Instant::now();

        let allow = match self.scan_ts {
            None => true,
            Some(w) if now >= w + self.cfg.max_scan_age => true,
            Some(w) if now >= w + self.cfg.min_scan_age && forced => true,
            _ => false
        };
        if allow {
            let result = self.c.scan().await?;
            self.scan_ts = Some(Instant::now());
            self.s.scan_ind(result);
        } 
        Ok(())
    }

    async fn bindc(mac: &str, dev: &mut Device, c: &GreeClient) -> Result<()> {
        if dev.key.is_none() {
            let pack = c.bind(dev.ip, mac).await?;
            dev.bind_ind(pack);
        }
        Ok(())
    }

    async fn net_read<T: NetVar>(mac: &str, dev: &Device, c: &GreeClient, vars: &mut NetVarBag<T>) -> Result<()> {
        let key = dev.key.as_ref().ok_or_else(|| Error::mac_not_bound(mac))?;
        let names: Vec<VarName> = vars
            .iter()
            .filter_map(|(name, nv)| if nv.is_net_read_pending() { Some(*name) } else { None })
            .collect();
        if names.is_empty() { return Ok(()) }
        let pack = c.getvars(dev.ip, mac, key, &names).await?;
        for (n, v) in pack.cols.into_iter().zip(pack.dat.into_iter()) { 
            if let Some(nv) = vars::name_of(&n).and_then(|n| vars.get_mut(n)) {
                nv.net_set(v);
            }
        }
        Ok(())
    }

    async fn net_write<T: NetVar>(mac: &str, dev: &Device, c: &GreeClient, vars: &mut NetVarBag<T>) -> Result<()> {
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
        let pack = c.setvars(dev.ip, mac, key, &names, &values).await?;
        for (n, v) in pack.opt.into_iter().zip(pack.p.into_iter()) {
            if let Some(nv) = vars::name_of(&n).and_then(|n| vars.get_mut(&n)) {
                nv.clear_net_write_pending();
                nv.net_set(v);
            }
        }
        Ok(())
    }

    async fn apply_dev<T: NetVar>(mac: &str, dev: &mut Device, c: &GreeClient, op: &mut Op<'_, T>) -> Result<()> {
        Self::bindc(mac, dev, c).await?;
        match op {
            Op::Bind => Ok(()),
            Op::NetRead(vars) => Self::net_read(mac, dev, c, *vars).await,
            Op::NetWrite(vars) => Self::net_write(mac, dev, c, *vars).await
        }
    }

    async fn apply<T: NetVar>(&mut self, target: &str, op: &mut Op<'_, T>) -> Result<()> {
        let mac = self.cfg.aliases.get(target).map(|s| s.as_str()).unwrap_or(target);
        let dev = self.s.devices.get_mut(mac).ok_or_else(||Error::not_found(target))?;
        Self::apply_dev(mac, dev, &self.c, op).await
    }

    /// applies Op to target; retries after forced scan on failure
    async fn apply_retrying<T: NetVar>(&mut self, target: &str, mut op: Op<'_, T>) -> Result<()> {
        let () = self.scan(false).await?;
        let r = self.apply(target, &mut op).await;
        if r.is_ok() { return r }
        let () = self.scan(true).await?;        
        self.apply(target, &mut op).await
    }

    fn with_device<R>(&self, target: &str, f: impl FnOnce(&Device) -> R) -> Result<R> {
        let mac = self.cfg.aliases.get(target).map(|s| s.as_str()).unwrap_or(target);
        let dev = self.s.devices.get(mac).ok_or_else(||Error::not_found(target))?;
        Ok(f(dev))    
    }

    /// applies f to the target's state; retries after forced scan on failure (i.e. if device not found)
    async fn with_device_retrying<R>(&mut self, target: &str, f: impl Fn(&Device) -> R) -> Result<R> {
        let () = self.scan(false).await?;
        let r = self.with_device(target, &f);
        if r.is_ok() { return r }
        let () = self.scan(true).await?;        
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
    pub async fn new(cfg: GreeConfig) -> Result<Self> { 
        Ok(Self { g: GreeInternal::new(cfg).await? })
    }

    /// Calls `f` with the current state
    pub async fn with_state<R>(&mut self, f: impl Fn(&GreeState) -> R) -> Result<R> {
        self.g.scan(false).await?;
        Ok(f(&self.g.s))
    }

    /// Calls `f` with the device specified as `target`
    /// 
    /// Performs forced scan if the device was not found.
    pub async fn with_device<R>(&mut self, target: &String, f: impl Fn(&Device) -> R) -> Result<R> {
        self.g.with_device_retrying(target, f).await
    }

    /// Reads pending variables from the network
    pub async fn net_read<T: NetVar>(&mut self, target: &str, vars: &mut NetVarBag<T>) -> Result<()> { 
        self.g.apply_retrying(target, Op::NetRead(vars)).await 
    }

    /// Writes pending variables to the network, and fills the netvar bag with the values returned from the network
    pub async fn net_write<T: NetVar>(&mut self, target: &str, vars: &mut NetVarBag<T>)  -> Result<()> {
        self.g.apply_retrying(target, Op::NetWrite(vars)).await
    }

    /// Executes the operation specified
    pub async fn execute<T: NetVar>(&mut self, target: &str, op: Op<'_, T>)  -> Result<()> {
        self.g.apply_retrying(target, op).await
    }

    /// Performs explicit scan
    pub async fn scan(&mut self) -> Result<()> { 
        self.g.scan(true).await 
    }

    /// Performs explicit bind
    /// 
    /// Note that this method is rarely needed, as binds are usually performed under-the-hood when necessary.
    pub async fn bind(&mut self, target: &String) -> Result<()> { 
        self.g.apply_retrying(target, Op::<SimpleNetVar>::Bind).await 
    }

}

