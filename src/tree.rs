use std::{time::SystemTime, collections::HashMap, net::IpAddr};

use serde_json::Value;

use crate::apdu::{ScanResponsePack, GenericMessage, BindResponsePack};

pub type MacAddr = String;

pub struct Tree {
    pub updated: SystemTime,
    /// by mac addr
    pub devices: HashMap<MacAddr, Device>
}

impl Tree {
    pub fn new(now: SystemTime) -> Self { Self { updated: now, devices: HashMap::new() } }
    pub fn scan_ind(&mut self, now: SystemTime, scan_result: Vec<(IpAddr, GenericMessage, ScanResponsePack)>) {
        self.updated = now;
        self.devices = scan_result.into_iter().map(|(ip, _, scan_result)| (
            scan_result.mac.clone(),
            Device { updated: now, ip, scan_result, key: None, values: HashMap::new() }
        )).collect();
    }
}

pub struct Device {
    pub updated: SystemTime,
    pub ip: IpAddr,
    pub scan_result: ScanResponsePack,
    pub key: Option<String>,
    pub values: HashMap<String, VarValue>
}

impl Device {
    pub fn bind_ind(&mut self, now: SystemTime, pack: BindResponsePack) {
        self.updated = now;
        self.key = Some(pack.key)
    }

    pub fn status_ind(&mut self, now: SystemTime, names: Vec<String>, values: Vec<Value>) {
        for (n, v) in names.into_iter().zip(values.into_iter()) {
            self.values.insert(n, VarValue { updated: now, value: v });
        }
    }
}

pub struct VarValue {
    pub updated: SystemTime,
    pub value: Value
}