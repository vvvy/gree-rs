use std::{time::Duration, collections::HashMap, net::IpAddr};

use serde_json::Value;

use crate::{apdu::{ScanResponsePack, GenericMessage, BindResponsePack}, vars::VarName};

pub type MacAddr = String;

pub struct GreeConfig {
    pub max_count: usize,
    pub bcast_addr: IpAddr,
    pub min_scan_age: Duration,
    pub max_scan_age: Duration,
}

impl GreeConfig {
    pub const DEFAULT_MAX_COUNT: usize = 10;
    pub const DEFAULT_BROADCAST_ADDR: [u8; 4] =  [10, 0, 0, 255];
    pub const DEFAULT_MIN_SCAN_AGE: Duration = Duration::from_secs(60);
    pub const DEFAULT_MAX_SCAN_AGE: Duration = Duration::from_secs(3600 * 24);
}

impl Default for GreeConfig {
    fn default() -> Self {
        Self { 
            max_count: Self::DEFAULT_MAX_COUNT, 
            bcast_addr: Self::DEFAULT_BROADCAST_ADDR.into(), 
            min_scan_age: Self::DEFAULT_MIN_SCAN_AGE, 
            max_scan_age: Self::DEFAULT_MAX_SCAN_AGE
        }
    }
}

pub struct GreeState {
    pub aliases: HashMap<String, MacAddr>,
    pub devices: HashMap<MacAddr, Device>,
}

impl GreeState {
    pub fn new() -> Self { Self { devices: HashMap::new(), aliases: HashMap::new() } }
    pub fn scan_ind(&mut self, scan_result: Vec<(IpAddr, GenericMessage, ScanResponsePack)>) {
        self.devices = scan_result.into_iter().map(|(ip, _, scan_result)| (
            scan_result.mac.clone(),
            Device { ip, scan_result, key: None }
        )).collect();
    }
}

pub struct Device {
    pub ip: IpAddr,
    pub scan_result: ScanResponsePack,
    pub key: Option<String>,
}

impl Device {
    pub fn bind_ind(&mut self, pack: BindResponsePack) {
        self.key = Some(pack.key)
    }
}

pub trait NetVar {
    //fn get_name(&self) -> &'static str;
    /// Sets network value and clears net_read_pending
    fn net_set(&mut self, value: Value);
    /// Gets network value
    fn net_get(&self) -> &Value;
    fn is_net_read_pending(&self) -> bool;
    fn is_net_write_pending(&self) -> bool;
    fn clear_net_write_pending(&mut self);
}

pub struct SimpleNetVar {
    value: Value,
    net_read_pending: bool,
    net_write_pending: bool,
}

impl SimpleNetVar {
    pub fn new() -> Self {
        Self { value: Value::Null, net_read_pending: true, net_write_pending: false }
    }

    pub fn from_value(value: Value) -> Self {
        Self { value, net_read_pending: false, net_write_pending: true }
    }

    pub fn user_set(&mut self, value: Value) {
        self.value = value;
        self.net_write_pending = true;
    }

    pub fn user_get(&self) -> &Value {
        &self.value
    }
}

impl NetVar for SimpleNetVar {
    //fn get_name(&self) -> &'static str { self.name }
    fn net_set(&mut self, value: Value) { 
        self.value = value;
        self.net_read_pending = false;
    }
    fn net_get(&self) -> &Value { &self.value }
    fn is_net_read_pending(&self) -> bool { self.net_read_pending }
    fn is_net_write_pending(&self) -> bool { self.net_write_pending }
    fn clear_net_write_pending(&mut self) { self.net_write_pending = false }
}

impl From<i32> for SimpleNetVar {
    fn from(value: i32) -> Self {
        Self::from_value(value.into())
    }
}

impl From<&str> for SimpleNetVar {
    fn from(value: &str) -> Self {
        Self::from_value(value.into())
    }
}


pub type NetVarBag<T> = HashMap<VarName, T>;

/// NetVar Operation
#[derive(Debug)]
pub enum Op<'t, T: NetVar> {
    Bind,
    NetRead(&'t mut NetVarBag<T>),
    NetWrite(&'t mut NetVarBag<T>),
}
