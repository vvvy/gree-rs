//! async client (tokio-based)
#![cfg(feature = "async_tokio")]

use std::{net::{SocketAddr, Ipv4Addr, IpAddr}, time::{Duration, Instant}};

use tokio::{select, net::UdpSocket, time};

use serde_json::Value;

use crate::{state::*, vars::VarName};


use super::*;

pub struct GreeClient {
    s: UdpSocket,
    recv_timeout: Duration

}

impl GreeClient {
    pub async fn new() -> Result<Self> {
        let sa: SocketAddr = (Ipv4Addr::UNSPECIFIED, 0/*PORT + 1*/).into();
        let s = UdpSocket::bind(sa).await?;
        let recv_timeout = Duration::from_secs(3);
        Ok(Self { s, recv_timeout })
    }

    async fn recv(&self) -> Result<(IpAddr, GenericMessage)> {
        let mut b = [0u8; 2000];
        let (len, addr) = select! {
            la = self.s.recv_from(&mut b) => { la? }
            _ = time::sleep(self.recv_timeout) => { Err("timeout")? }
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

    pub async fn scan(&self, bcast_addr: IpAddr, max_count: usize) -> Result<Vec<(IpAddr, GenericMessage, ScanResponsePack)>> {
        self.s.send_to(scan_request(), (bcast_addr, PORT)).await?;
    
        let mut rv = vec![];
    
        for _ in 0..max_count {
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
    
    pub async fn bind(&self, addr: IpAddr, mac: &str) -> Result<BindResponsePack> {
        let gm = bind_request(mac, GENERIC_KEY)?;
        let ogm = self.exchange(addr, &gm).await?;
        Ok(handle_response(addr, &ogm.pack, GENERIC_KEY)?)
    }

    pub async fn status(&self, addr: IpAddr, mac: &str, key: &str, vars: &[&str]) -> Result<StatusResponsePack> {
        let gm = status_request(mac, key, vars)?;
        let ogm = self.exchange(addr, &gm).await?;
        Ok(handle_response(addr, &ogm.pack, key)?)
    }

    pub async fn setvars(&self, addr: IpAddr, mac: &str, key: &str, names: &[&'static str], values: &[Value]) -> Result<CommandResponsePack> {
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
            c: GreeClient::new().await?,
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
            let result = self.c.scan(self.cfg.bcast_addr, self.cfg.max_count).await?;
            self.scan_ts = Some(Instant::now());
            self.s.scan_ind(result);
        } 
        Ok(())
    }

    async fn bindc(mac: &MacAddr, dev: &mut Device, c: &GreeClient) -> Result<()> {
        if dev.key.is_none() {
            let pack = c.bind(dev.ip, mac).await?;
            dev.bind_ind(pack);
        }
        Ok(())
    }

    async fn net_read<T: NetVar>(mac: &MacAddr, dev: &Device, c: &GreeClient, vars: &mut NetVarBag<T>) -> Result<()> {
        let key = dev.key.as_ref().ok_or_else(|| format!("{mac} not bound"))?;
        let names: Vec<VarName> = vars
            .iter()
            .filter_map(|(name, nv)| if nv.is_net_read_pending() { Some(*name) } else { None })
            .collect();
        if names.is_empty() { return Ok(()) }
        let pack = c.status(dev.ip, mac, key, &names).await?;
        for (n, v) in pack.cols.into_iter().zip(pack.dat.into_iter()) { 
            if let Some(nv) = vars::name_of(&n).and_then(|n| vars.get_mut(n)) {
                nv.net_set(v);
            }
        }
        Ok(())
    }

    async fn net_write<T: NetVar>(mac: &MacAddr, dev: &Device, c: &GreeClient, vars: &mut NetVarBag<T>) -> Result<()> {
        let key = dev.key.as_ref().ok_or_else(|| format!("{mac} not bound"))?;

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

    async fn apply_dev<T: NetVar>(mac: &MacAddr, dev: &mut Device, c: &GreeClient, op: &mut Op<'_, T>) -> Result<()> {
        Self::bindc(mac, dev, c).await?;
        match op {
            Op::Bind => Ok(()),
            Op::NetRead(vars) => Self::net_read(mac, dev, c, *vars).await,
            Op::NetWrite(vars) => Self::net_write(mac, dev, c, *vars).await
        }
    }

    async fn apply<T: NetVar>(&mut self, target: &String, op: &mut Op<'_, T>) -> Result<()> {
        let mac = self.cfg.aliases.get(target).unwrap_or(target);
        let dev = self.s.devices.get_mut(mac).ok_or_else(||"not found")?;
        Self::apply_dev(mac, dev, &self.c, op).await
    }

    /// applies Op to target; retries after forced scan on failure
    async fn apply_retrying<T: NetVar>(&mut self, target: &String, mut op: Op<'_, T>) -> Result<()> {
        let () = self.scan(false).await?;
        let r = self.apply(target, &mut op).await;
        if r.is_ok() { return Ok(());}
        let () = self.scan(true).await?;        
        self.apply(target, &mut op).await
    }

}

pub struct Gree {
    g: GreeInternal,
}

impl Gree {

    pub async fn new() -> Result<Self> {
        Ok(Self { g: GreeInternal::new(Default::default()).await? })
    }

    pub async fn from_config(cfg: GreeConfig) -> Result<Self> { 
        Ok(Self { g: GreeInternal::new(cfg).await? })
    }

    pub fn state(&self) -> &GreeState { &self.g.s }

    /// Performs scan and fills state
    pub async fn scan(&mut self) -> Result<()> { 
        self.g.scan(false).await 
    }

    /// Binds 
    pub async fn bind(&mut self, target: &String) -> Result<()> { 
        self.g.apply_retrying(target, Op::<SimpleNetVar>::Bind).await 
    }

    /// Reads pending variables from the network
    pub async fn net_read<T: NetVar>(&mut self, target: &String, vars: &mut NetVarBag<T>) -> Result<()> { 
        self.g.apply_retrying(target, Op::NetRead(vars)).await 
    }

    /// Writes pending variables to the network
    pub async fn net_write<T: NetVar>(&mut self, target: &String, vars: &mut NetVarBag<T>)  -> Result<()> {
        self.g.apply_retrying(target, Op::NetWrite(vars)).await
    }

}

