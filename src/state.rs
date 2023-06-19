use std::{time::Duration, collections::HashMap, net::{IpAddr, SocketAddr, Ipv4Addr}};

use serde_json::Value;

use crate::{*, apdu::{ScanResponsePack, GenericMessage, BindResponsePack}, vars::VarName};

pub type MacAddr = String;

/// Low-level Gree client configuration
#[derive(Debug, Clone, Copy)]
pub struct GreeClientConfig {
    /// Recv datagram buffer size
    pub buffer_size: usize,
    /// Socket recv timeout
    pub recv_timeout: Duration,
    /// Socket addr to bind to
    pub bind_addr: SocketAddr,
    /// Maximum devices to be discovered diring a scan. The scan is stopped early when this number of devices is reached.
    pub max_count: usize,
    /// Broadcast address for the network.
    pub bcast_addr: IpAddr,
}

impl GreeClientConfig {
    pub const DEFAULT_BUFFER_SIZE: usize = 2048;
    pub const DEFAULT_MAX_COUNT: usize = 10;
    pub const DEFAULT_BROADCAST_ADDR: [u8; 4] =  [10, 0, 0, 255];
    pub const DEFAULT_RECV_TIMEOUT: Duration = Duration::from_secs(3);
}

impl Default for GreeClientConfig {

    fn default() -> Self {
        Self {
            buffer_size: Self::DEFAULT_BUFFER_SIZE,
            recv_timeout: Self::DEFAULT_RECV_TIMEOUT,
            bind_addr: (Ipv4Addr::UNSPECIFIED, 0).into(),
            max_count: Self::DEFAULT_MAX_COUNT, 
            bcast_addr: Self::DEFAULT_BROADCAST_ADDR.into(), 
        }
    }
}

/// Gree network configuration
#[derive(Debug, Clone)]
pub struct GreeConfig {
    /// lower level client configuration
    pub client_config: GreeClientConfig,
    /// Minimum scan age. Scan is always bypassed if the last successful scan is younger than this value. 
    pub min_scan_age: Duration,
    /// Maximum scan age. Scan is forced if the last (successful) scan is older than this value.
    pub max_scan_age: Duration,
    /// Aliases for the network devices
    pub aliases: HashMap<String, MacAddr>,
}

impl GreeConfig {

    pub const DEFAULT_MIN_SCAN_AGE: Duration = Duration::from_secs(60);
    pub const DEFAULT_MAX_SCAN_AGE: Duration = Duration::from_secs(3600 * 24);
}

impl Default for GreeConfig {
    fn default() -> Self {
        Self {
            client_config: Default::default(),
            min_scan_age: Self::DEFAULT_MIN_SCAN_AGE, 
            max_scan_age: Self::DEFAULT_MAX_SCAN_AGE,
            aliases: HashMap::new(),
        }
    }
}

/// State of Gree network
pub struct GreeState {
    pub devices: HashMap<MacAddr, Device>,
}

impl GreeState {
    pub fn new() -> Self { Self { devices: HashMap::new() } }
    pub fn scan_ind(&mut self, scan_result: Vec<(IpAddr, GenericMessage, ScanResponsePack)>) {
        self.devices = scan_result.into_iter().map(|(ip, _, scan_result)| (
            scan_result.mac.clone(),
            Device { ip, scan_result, key: None }
        )).collect();
    }
}

/// Holds information about a Device on the network.
/// 
/// Devices are typically discovered during scans. The `key` field is set as a result of successful binding.
pub struct Device {
    /// Known IP address of the device. 
    pub ip: IpAddr,

    /// Device's scan respobse
    pub scan_result: ScanResponsePack,

    /// Encryption key (if bound)
    pub key: Option<String>,
}

impl Device {
    pub fn bind_ind(&mut self, pack: BindResponsePack) {
        self.key = Some(pack.key)
    }
}


/// Network Variable (NetVar) defines a protocol for exchanging Values with the network.
/// 
/// It may be considered a placeholder for a Value that can be read from or written to the network.
pub trait NetVar {
    /// Stores the value received from the network and clears net_read_pending
    fn net_set(&mut self, value: Value);
    /// Returns the value to be written to the network
    fn net_get(&self) -> &Value;
    /// True if the value of this NetVar is supposed to be read and set from the network
    fn is_net_read_pending(&self) -> bool;
    /// True if the value of this NetVar is supposed to be written to the network
    fn is_net_write_pending(&self) -> bool;
    /// Signal that the value of this NetVar doesn't need to be written to the network anymore (typically after a successful net write)
    fn clear_net_write_pending(&mut self);
}


/// A basic implementation of [NetVar]
pub struct SimpleNetVar {
    value: Value,
    net_read_pending: bool,
    net_write_pending: bool,
}

impl SimpleNetVar {
    pub fn new() -> Self {
        Self { value: Value::Null, net_read_pending: true, net_write_pending: false }
    }

    pub fn add_nv_to(mut bag: NetVarBag<Self>, (name, value): (impl AsRef<str>, impl AsRef<str>)) -> Result<NetVarBag<Self>> {
        let name = vars::name_of(name.as_ref())
            .ok_or_else(|| Error::InvalidVar(name.as_ref().to_owned()))?;
        let value = vars::parse_value(name, value)?;
        bag.insert(name, Self::from_value(value));
        Ok(bag)
    }

    pub fn add_n_to(mut bag: NetVarBag<Self>, name: impl AsRef<str>) -> Result<NetVarBag<Self>> {
        let name = vars::name_of(name.as_ref())
            .ok_or_else(|| Error::InvalidVar(name.as_ref().to_owned()))?;
        bag.insert(name, Self::new());
        Ok(bag)
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

/// A collection of network variables by internalized name
pub type NetVarBag<T> = HashMap<VarName, T>;

/// Constructs NetVarBag from an iterator of names. The bag returned is ready to be used in a network read call.
pub fn net_var_bag_from_names<'t, S: AsRef<str> + 't>(mut ns: impl Iterator<Item = &'t S>) -> Result<NetVarBag<SimpleNetVar>> {
    ns.try_fold(std::collections::HashMap::new(), SimpleNetVar::add_n_to)
}

/// Constructs NetVarBag from an iterator of (name, value) pairs. The bag returned is ready to be used in a network write call.
pub fn net_var_bag_from_nvs<'t, S: AsRef<str> + 't>(mut nvs: impl Iterator<Item = (&'t S, &'t S)>) -> Result<NetVarBag<SimpleNetVar>> {
    nvs.try_fold(std::collections::HashMap::new(), SimpleNetVar::add_nv_to)
}

/// Converts NetVarBag into a json. Convenient for value reporting.
pub fn net_var_bag_to_json<T: NetVar>(b: &NetVarBag<T>) -> HashMap<VarName, Value> {
    b.into_iter().map(|(k, v)| (*k, v.net_get().clone())).collect()
}

/// Constructs NetVarBag of [SimpleNetVar]s, for reading (from keys) or writing (from key => value pairs)
#[macro_export]
macro_rules! net_var_bag {
    ($($var:expr => $val:expr),+) => {
        [$(($var, $val)),+].into_iter().try_fold(std::collections::HashMap::new(), gree::SimpleNetVar::add_nv_to)
    };
    ($($var:expr),+) => {
        [$($var),+].into_iter().try_fold(std::collections::HashMap::new(), gree::SimpleNetVar::add_n_to)
    };
}

/// NetVar Operation
#[derive(Debug)]
pub enum Op<'t, T: NetVar> {
    Bind,
    NetRead(&'t mut NetVarBag<T>),
    NetWrite(&'t mut NetVarBag<T>),
}
