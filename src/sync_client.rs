use std::{net::{Ipv4Addr, UdpSocket, SocketAddr, IpAddr}, time::Duration, sync::mpsc::{Sender, Receiver}};
use serde_json::Value;

use super::*;


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

    pub fn new() -> Result<Self> {
        let sa: SocketAddr = (Ipv4Addr::UNSPECIFIED, PORT + 1).into();
        let s = UdpSocket::bind(sa)?;
        let sr = s.try_clone()?;
        let (send, r) = std::sync::mpsc::channel();
        std::thread::spawn(|| if let Err(e) = Self::recv_loop(sr, send) { error!("Recv: {e}") });
        let recv_timeout = Duration::from_secs(3);
        Ok(Self { s, r, recv_timeout })
    }

    pub fn scan(&self, bcast_addr: IpAddr, max_count: usize) -> Result<Vec<(SocketAddr, GenericMessage, ScanResponsePack)>> {
        self.s.set_read_timeout(Some(Duration::from_secs(3)))?;
        self.s.send_to(scan_request(), (bcast_addr, PORT))?;
    
        let mut rv = vec![];
    
        for _ in 0..max_count {
            match self.r.recv_timeout(self.recv_timeout) {
                Ok((addr, gm)) => {
                    let pack = decode_response(&gm.pack, GENERIC_KEY)?;
                    trace!("[{}] pack raw: {}", addr, pack);
                    let pack = serde_json::from_str(&pack)?;
                    debug!("[{}] pack: {:?}", addr, pack);
                    rv.push((addr, gm, pack));
                } 
                Err(_) => break, //timeout
            }
        }
        Ok(rv)
    }
    
    pub fn bind(&self, addr: IpAddr, mac: &str) -> Result<BindResponsePack> {
        let gm = bind_request(mac, GENERIC_KEY)?;
        let ogm = self.exchange(addr, &gm)?;

        let pack = decode_response(&ogm.pack, GENERIC_KEY)?;
        trace!("[{}] pack raw: {}", addr, pack);
        let pack: BindResponsePack = serde_json::from_str(&pack)?;
        debug!("[{}] pack: {:?}", addr, pack);
        Ok(pack)
    }

    pub fn status(&self, addr: IpAddr, mac: &str, key: &str) -> Result<StatusResponsePack> {
        let gm = status_request(mac, key.as_bytes(), None)?;
        let ogm = self.exchange(addr, &gm)?;

        let pack = decode_response(&ogm.pack, key.as_bytes())?;
        trace!("[{}] pack raw: {}", addr, pack);
        let pack: StatusResponsePack = serde_json::from_str(&pack)?;
        debug!("[{}] pack: {:?}", addr, pack);
        Ok(pack)
    }

    pub fn setvars(&self, addr: IpAddr, mac: &str, key: &str, names: &[&'static str], values: &[Value]) -> Result<CommandResponsePack> {
        let gm = setvar_request(mac, key.as_bytes(), names, values)?;
        let ogm = self.exchange(addr, &gm)?;
        Ok(handle_response(addr, &ogm.pack, key)?)
    }

}
