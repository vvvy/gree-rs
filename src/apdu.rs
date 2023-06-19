//! Application protocol data units
use std::fmt::Debug;
use std::net::IpAddr;

use serde::de;
use serde_derive::{Serialize, Deserialize};
//use serde_json::{json, Value};

use base64::{Engine as _, engine::general_purpose};

use aes::Aes128;
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit, generic_array::GenericArray };
use serde_json::Value;

use crate::*;
type Int = i32;

/// Constants and definitions for Gree parameters and enumerations for their possible values
pub mod vars {

pub type VarName = &'static str;

#[repr(i32)]
pub enum OnOff {
    Off = 0,
    On = 1
}


/// `Pow`: power state of the device
/// * 0: off
/// * 1: on
pub const POW: VarName = "Pow";

pub type Pow = OnOff;

/// `Mod`: mode of operation
/// * 0: auto
/// * 1: cool
/// * 2: dry
/// * 3: fan
/// * 4: heat
pub const MOD: VarName = "Mod";

#[repr(i32)]
pub enum Mod {
    Auto = 0,
    Cool = 1,
    Dry = 2,
    Fan = 3,
    Heat = 4,
}

/// `SetTem` and `TemUn`: set temperature and temperature unit
/// * if `TemUn` = 0, `SetTem` is the set temperature in Celsius
/// * if `TemUn` = 1, `SetTem` is the set temperature is Fahrenheit
pub const SET_TEM: VarName = "SetTem";

/// `SetTem` and `TemUn`: set temperature and temperature unit
/// * if `TemUn` = 0, `SetTem` is the set temperature in Celsius
/// * if `TemUn` = 1, `SetTem` is the set temperature is Fahrenheit
pub const TEM_UN: VarName = "TemUn";

#[repr(i32)]
pub enum TemUn {
    Celsius = 0,
    Fahrenheit = 1,
}

/// `WdSpd`: fan speed
/// * 0: auto
/// * 1: low
/// * 2: medium-low (not available on 3-speed units)
/// * 3: medium
/// * 4: medium-high (not available on 3-speed units)
/// * 5: high
pub const WD_SPD: VarName = "WdSpd";

#[repr(i32)]
pub enum WdSpd {
    Auto = 0,
    Low = 1,
    MediumLow = 2,
    Medium = 3,
    MediumHigh = 4,
    High = 5,
}

/// `Air`: controls the state of the fresh air valve (not available on all units)
/// * 0: off
/// * 1: on
pub const AIR: VarName = "Air";

pub type Air = OnOff;

/// `Blo`: "Blow" or "X-Fan", this function keeps the fan running for a while after shutting down. Only usable in Dry and Cool mode
pub const BLO: &str = "Blo";

pub type Blo = OnOff;

/// `Health`: controls Health ("Cold plasma") mode, only for devices equipped with "anion generator", which absorbs dust and kills bacteria
/// * 0: off
/// * 1: on
pub const HEALTH: VarName = "Health";

pub type Health = OnOff;

/// `SwhSlp`: sleep mode, which gradually changes the temperature in Cool, Heat and Dry mode
/// * 0: off
/// * 1: on
pub const SWH_SLP: VarName = "SwhSlp";

pub type SwhSlp = OnOff;

/// `Lig`: turns all indicators and the display on the unit on or off
/// * 0: off
/// * 1: on
pub const LIG: VarName = "Lig";

pub type Lig = OnOff;

/// `SwingLfRig`: controls the swing mode of the horizontal air blades (available on limited number of devices, e.g. some Cooper & Hunter units - thanks to mvmn)
/// * 0: default
/// * 1: full swing
/// * 2-6: fixed position from leftmost to rightmost
/// 
/// Full swing, like for SwUpDn is not supported
pub const SWING_LF_RIG: VarName = "SwingLfRig";

#[repr(i32)]
pub enum SwingLfRig {
    Default = 0,
    Full = 1,
    Pos0 = 2,
    Pos1 = 3,
    Pos2 = 4,
    Pos3 = 5,
    Pos4 = 6
}


/// `SwUpDn`: controls the swing mode of the vertical air blades
/// * 0: default
/// * 1: swing in full range
/// * 2: fixed in the upmost position (1/5)
/// * 3: fixed in the middle-up position (2/5)
/// * 4: fixed in the middle position (3/5)
/// * 5: fixed in the middle-low position (4/5)
/// * 6: fixed in the lowest position (5/5)
/// * 7: swing in the downmost region (5/5)
/// * 8: swing in the middle-low region (4/5)
/// * 9: swing in the middle region (3/5)
/// * 10: swing in the middle-up region (2/5)
/// * 11: swing in the upmost region (1/5)
pub const SW_UP_DN: VarName = "SwUpDn";

#[repr(i32)]
pub enum SwUpDn {
    Default = 0,
    Full = 1,
    Fixed1 = 2,
    Fixed2 = 3,
    Fixed3 = 4,
    Fixed4 = 5,
    Fixed5 = 6,
    Swing5 = 7,
    Swing4 = 8,
    Swing3 = 9,
    Swing2 = 10,
    Swing1 = 11
}

/// `Quiet`: controls the Quiet mode which slows down the fan to its most quiet speed. Not available in Dry and Fan mode.
/// * 0: off
/// * 1: on
pub const QUIET: VarName = "Quiet";

pub type Quiet = OnOff;

/// `Tur`: sets fan speed to the maximum. Fan speed cannot be changed while active and only available in Dry and Cool mode.
/// * 0: off
/// * 1: on
pub const TUR: VarName = "Tur";

pub type Tur = OnOff;

/// `StHt`: maintain the room temperature steadily at 8°C and prevent the room from freezing by heating operation when nobody 
/// is at home for long in severe winter (from <http://www.gree.ca/en/features>)
pub const ST_HT: VarName = "StHt"; 

/// `HeatCoolType`: unknown
pub const HEAT_COOL_TYPE: VarName = "HeatCoolType"; 

/// `TemRec`: this bit is used to distinguish between two Fahrenheit values (see Setting the temperature using Fahrenheit section below)
pub const TEM_REC: VarName = "TemRec"; 

/// `SvSt`: energy saving mode
/// * 0: off
/// * 1: on
pub const SV_ST: VarName = "SvSt";

pub type SvSt = OnOff;

/// `TemSen`: internal temperature sensor value (READ ONLY)
/// 
/// The value is in celsius and has an offset of +40 to avoid using negative values. 
/// For example if you get 65 from the device it means the current temperature is 65 - 40 = 25.
pub const TEM_SEN: VarName = "TemSen";

/// `time`: read or set device time. Requires custom pack and must be used separately from other vars.
/// 
/// Format: "2018-05-11 19:42:01"
pub const TIME: VarName = "time";

//------------------------------------------------------------------------------------------------------------------------------
pub const ALL: [VarName; 20] = [
    POW, 
    MOD, 
    SET_TEM, 
    TEM_UN, 
    WD_SPD,
    AIR,
    BLO,
    HEALTH,
    SWH_SLP,
    LIG,
    SWING_LF_RIG,
    SW_UP_DN,
    QUIET,
    TUR,
    ST_HT,
    HEAT_COOL_TYPE,
    TEM_REC,
    SV_ST,
    TEM_SEN,
    TIME,
];

/// Internalizes name of variable
pub fn name_of(n: &str) -> Option<VarName> {
    match n {
        POW => Some(POW),
        MOD => Some(MOD),
        SET_TEM => Some(SET_TEM),
        TEM_UN => Some(TEM_UN),
        WD_SPD => Some(WD_SPD),
        AIR => Some(AIR),
        BLO => Some(BLO),
        HEALTH => Some(HEALTH),
        SWH_SLP => Some(SWH_SLP),
        LIG => Some(LIG),
        SWING_LF_RIG => Some(SWING_LF_RIG),
        SW_UP_DN => Some(SW_UP_DN),
        QUIET => Some(QUIET),
        TUR => Some(TUR),
        ST_HT => Some(ST_HT),
        HEAT_COOL_TYPE => Some(HEAT_COOL_TYPE),
        TEM_REC => Some(TEM_REC),
        SV_ST => Some(SV_ST),
        TEM_SEN => Some(TEM_SEN),
        TIME => Some(TIME),
        _ => None,
    }
}

use crate::{Result, Value, Error};

/// Parses value for the specified variable
pub fn parse_value(name: VarName, value: impl AsRef<str>) -> Result<Value> {
    Ok(match name {
        //Arbitrary string so far (TODO: enforce format)
        TIME => {
            Value::String(value.as_ref().to_owned())
        }
        //{0,1}
        POW | TEM_UN | AIR | BLO | HEALTH | SWH_SLP | LIG | QUIET | TUR | SV_ST | ST_HT => {
            let w: u8 = value.as_ref().parse()?;
            if w > 1 { return Err(Error::invalid_value(name, value.as_ref())) }
            Value::Number(w.into())
        }
        //u8
        MOD | SET_TEM | TEM_REC | WD_SPD | SWING_LF_RIG | SW_UP_DN  => {
            let w: u8 = value.as_ref().parse()?;
            Value::Number(w.into())
        }
        //the rest is assumed string
        _ => {
            //let w: u8 = value.as_ref().parse()?;
            //Value::Number(w.into())
            value.as_ref().into()
        }
    })
}

}

pub const SCAN_MESSAGE: &[u8] = br#"{
  "t": "scan"
}"#;
//const SM2: Value = json!({"t":"scan"});


#[derive(Deserialize, Debug)]
pub struct GenericMessage {
    #[serde(default)]
    pub cid: String,
    
    #[serde(default)]
    pub i: Int,
    
    #[serde(default)]
    pub pack: String,

    #[serde(default)]
    pub t: String,
    
    #[serde(default)]
    pub tcid: String,

    #[serde(default)]
    pub uid: Int,
}


#[derive(Serialize)]
pub struct GenericOutMessage<'t> {
    pub cid: &'t str,
    pub i: Int,
    pub pack: String,
    pub t:  &'t str,
    pub tcid:  &'t str,
    pub uid: Int,
}

#[derive(Deserialize, Debug)]
pub struct ScanResponsePack {
    #[serde(default)]
    pub t: String,

    #[serde(default)]
    pub cid: String,

    #[serde(default)]
    pub bc: String,

    #[serde(default)]
    pub brand: String,

    #[serde(default)]
    pub catalog:String,

    #[serde(default)]
    pub mac: String, // !!!

    #[serde(default)]
    pub mid: String,

    #[serde(default)]
    pub model: String,

    #[serde(default)]
    pub name: String,

    #[serde(default)]
    pub lock: i32,

    #[serde(default)]
    pub series: String,
    
    #[serde(default)]
    pub vender: String,
    
    #[serde(default)]
    pub ver: String
}



pub fn scan_request() -> &'static [u8] { SCAN_MESSAGE }

//------------------------------------------------------------------------------------------------------------------------------
/* {
"mac": "<MAC address>",
"t": "bind",
"uid": 0
} */

#[derive(Serialize)]
pub struct BindRequestPack<'t> {
    mac: &'t str,
    t: &'t str,
    uid: Int,
}

/* {
  "t": "bindok",
  "mac": "<MAC address>",
  "key": "<unique AES key>",
  "r": 200
} */

#[derive(Debug, Deserialize)]
pub struct BindResponsePack {
    pub t: String,
    pub mac: String,
    pub key: String,
    pub r: Int
}

pub fn bind_request<'t>(mac: &'t str, key: &str) -> Result<GenericOutMessage<'t>> {

    /* {
    "mac": "<MAC address>",
    "t": "bind",
    "uid": 0
    }*/
    let pack = serde_json::to_vec(&BindRequestPack {
        mac,
        t: "bind",
        uid: 0
    })?;

    let pack = encode_request(pack, key.as_bytes());

    /*
    {
    "cid": "app",
    "i": 1,
    "pack": "<encrypted, encoded pack>",
    "t": "pack",
    "tcid": "<MAC address>",
    "uid": 0
    }
    */

    Ok(GenericOutMessage {
        cid: "app",
        i: 1,
        pack,
        t: "pack",
        tcid: mac,
        uid: 0
    })
}




//------------------------------------------------------------------------------------------------------------------------------
/* {
  "cols": [
    "Pow", 
    "Mod", 
    "SetTem", 
    "WdSpd", 
    "Air", 
    "Blo", 
    "Health", 
    "SwhSlp", 
    "Lig", 
    "SwingLfRig", 
    "SwUpDn", 
    "Quiet", 
    "Tur", 
    "StHt", 
    "TemUn", 
    "HeatCoolType", 
    "TemRec", 
    "SvSt"
  ],
  "mac": "<MAC address>",
  "t": "status"
} */
#[derive(Serialize)]
pub struct StatusRequestPack<'t> {
    cols: &'t[&'t str], 
    mac: &'t str,
    t: &'t str,
}


/* {
  "t": "dat",
  "mac": "<MAC address>",
  "r": 200,
  "cols": [
    "Pow", 
    "Mod", 
    "SetTem", 
    "WdSpd", 
    "Air", 
    "Blo",
    "Health", 
    "SwhSlp", 
    "Lig", 
    "SwingLfRig", 
    "SwUpDn", 
    "Quiet", 
    "Tur", 
    "StHt", 
    "TemUn", 
    "HeatCoolType", 
    "TemRec", 
    "SvSt"
  ],
  "dat": [1, 1, 25, 1, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]
} */
#[derive(Debug, Deserialize)]
pub struct StatusResponsePack {
    pub t: String,
    pub mac: String,
    pub r: Int,
    pub cols: Vec<String>,
    pub dat: Vec<Value>,
}

pub fn status_request<'t>(mac: &'t str, key: &str, variables: &[&str]) -> Result<GenericOutMessage<'t>> {
    let pack = serde_json::to_vec(&StatusRequestPack {
        cols: variables,
        mac,
        t: "status",
    })?;

    let pack = encode_request(pack, key.as_bytes());

    /* {
    "cid": "app",
    "i": 0,
    "pack": "<encrypted, encoded pack>",
    "t": "pack",
    "tcid": "<MAC address>",
    "uid": 0
    } */

    Ok(GenericOutMessage {
        cid: "app",
        i: 0,
        pack,
        t: "pack",
        tcid: mac,
        uid: 0
    })

}

//------------------------------------------------------------------------------------------------------------------------------

/* {
"opt": ["TemUn", "SetTem"],
"p": [0, 27],
"t": "cmd"
} */

#[derive(Serialize)]
pub struct CommandPack<'t> {
    opt: &'t[&'t str], 
    p: &'t[Value],
    t: &'t str,
}

/* {
  "t": "res",
  "mac": "<MAC address>",
  "r": 200,
  "opt": ["TemUn", "SetTem"],
  "p": [0, 27],
  "val": [0, 27]
} */
#[derive(Debug, Deserialize)]
pub struct CommandResponsePack {
    pub t: String,
    pub mac: String,
    pub r: Int,
    pub opt: Vec<String>,
    pub p: Vec<Value>,

    #[serde(default)]
    pub val: Vec<Value>,
}


pub fn setvar_request<'t>(mac: &'t str, key: &str, names: &[&str], values: &[Value]) -> Result<GenericOutMessage<'t>> {
    /* {
    "opt": ["TemUn", "SetTem"],
    "p": [0, 27],
    "t": "cmd"
    } */
    let pack = serde_json::to_vec(&CommandPack {
        opt: names,
        p: values,
        t: "cmd",
    })?;

    let pack = encode_request(pack, key.as_bytes());


    /* {
    "cid": "app",
    "i": 0,
    "pack": "<encrypted, encoded pack>",
    "t": "pack",
    "tcid": "<MAC address>",
    "uid": 0
    } */

    Ok(GenericOutMessage {
        cid: "app",
        i: 0,
        pack,
        t: "pack",
        tcid: mac,
        uid: 0
    })
}


pub fn handle_response<T: de::DeserializeOwned + Debug>(addr: IpAddr, pack:&str, key: &str) -> Result<T> {
    let pack = decode_response(pack, key)?;
    trace!("[{}] pack raw: {}", addr, pack);
    let pack: T = serde_json::from_str(&pack)?;
    debug!("[{}] pack: {:?}", addr, pack);
    Ok(pack)
}

//------------------------------------------------------------------------------------------------------------------------------

fn pkcs7_unpad(payload: &mut Vec<u8>) {
    if let Some(b) = payload.last() { 
        for _ in 0..*b {
            payload.pop();
        }
    }
}

fn pkcs7_pad(payload: &mut Vec<u8>, blocksize: u8) {
    let pad_len = blocksize - ((payload.len() % (blocksize as usize)) as u8);
    for _ in 0..pad_len {
        payload.push(pad_len);
    }
}

pub fn decode_response(pack: &str, key: &str) -> Result<String> {
    let key = GenericArray::clone_from_slice(key.as_bytes());
    let cipher = Aes128::new(&key);
    let blocksize = 16;

    let mut payload = general_purpose::STANDARD.decode(pack)?;

    for pos in (0..payload.len()).step_by(blocksize) {
        let slice = &mut payload[pos..pos+blocksize];
        let mut block = GenericArray::clone_from_slice(slice);
        cipher.decrypt_block(&mut block);
        slice.copy_from_slice(block.as_slice())
    }
    pkcs7_unpad(&mut payload);
    Ok(String::from_utf8_lossy(&payload).to_string())
}

pub fn encode_request(mut payload: Vec<u8>, key: &[u8]) -> String {
    let key = GenericArray::clone_from_slice(key);
    let cipher = Aes128::new(&key);
    let blocksize = 16;

    pkcs7_pad(&mut payload, blocksize as u8);

    for pos in (0..payload.len()).step_by(blocksize) {
        let slice = &mut payload[pos..pos+blocksize];
        let mut block = GenericArray::clone_from_slice(slice);
        cipher.encrypt_block(&mut block);
        slice.copy_from_slice(block.as_slice())   
    }

    general_purpose::STANDARD.encode(payload)
}


