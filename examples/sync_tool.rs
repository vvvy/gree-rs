use gree::{*, sync_client::*};
use log::info;
use std::net::{IpAddr, Ipv4Addr};

const BCAST_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255));

enum Op {
    Help,
    Scan,
    Bind,
    Status
}

struct Args {
    op: Option<Op>,
    bcast: IpAddr,
    count: usize,
    mac: Option<String>,
    ip: Option<IpAddr>,
    key: Option<String>,
}

impl Default for Args {
    fn default() -> Self {
        Self { 
            op: None,
            bcast: BCAST_ADDR,
            count: 10, 
            mac: None, 
            ip: None, 
            key: None,
        }
    }
}

fn help() {
    let a = Args::default();
    println!(r#"
Gree Command Line Interface

Usage

sync_tool --scan|-s [ --bcast|-a <broadcast-addr({bcast})> ] [ --count|-c <max-devices({count})> ]
sync_tool --bind|-b --ip|-i <device-ip-address> --mac|-m <device-mac-adress>
sync_tool --status|-t --ip|-i <device-ip-address> --mac|-m <device-mac-adress> --key|-k <device-key>
"#,
bcast=a.bcast,
count=a.count
)
}

fn getcmdln() -> Args {
    let mut args = Args::default();

    let o: Option<String> = std::env::args().skip(1).fold(None, 
        |s, a| if let Some(arg) = s {
            match arg.as_ref() {
                "--mac" | "-m" => args.mac = Some(a),
                "--bcast" | "-a" => args.bcast = a.parse().expect("invalid --bcast"),
                "--count" | "-c" => args.count = a.parse().expect("invalid --count"),
                "--ip" | "-i" => args.ip = Some( a.parse().expect("invalid --ip")),
                "--key" | "-k" => args.key = Some(a),
                other => panic!("`{other}` invalid")
            }
            None
        } else {
            match a.as_ref() {
                "--help" | "-h" => args.op = Some(Op::Help),
                "--bind" | "-b" => args.op = Some(Op::Bind),
                "--scan" | "-s" => args.op = Some(Op::Scan),
                "--status" | "-t" => args.op = Some(Op::Status),
                _ => return Some(a)
            }
            None
        }
    );
    if let Some(o) = o {
        panic!("`{o}` invalid (at EOF)")
    }
    args

}


fn main() -> Result<()> {
    env_logger::init();
    info!("starting up");

    let args = getcmdln();

    let c = GreeClient::new()?;

    match args.op {
        Some(Op::Scan) => {
            let devs = c.scan(args.bcast, args.count)?;
            for (a, s, p) in devs {
                println!("{a}");
                println!("{s:?}");
                println!("{p:?}");
                println!("--------");
            }
        }
        Some(Op::Bind) => {
            let ip = args.ip.expect("Must specify --ip");
            let mac = args.mac.expect("Must specify --mac");
            let r = c.bind(ip, &mac)?;
            println!("{r:?}");
        }
        Some(Op::Status) => {
            let ip = args.ip.expect("Must specify --ip");
            let mac = args.mac.expect("Must specify --mac");
            let key = args.key.expect("Must specify --key");
            let r = c.status(ip, &mac, &key)?;
            println!("{r:?}");            
        }
        Some(Op::Help) | None => {
            help()
        }
    }

    Ok(())
}