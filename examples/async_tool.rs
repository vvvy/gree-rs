use gree::{*, async_client::*};
use log::info;
use std::{net::{IpAddr, Ipv4Addr}, str::FromStr};
use warp::Filter;

const BCAST_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255));

enum Op {
    Help,
    Scan,
    Bind,
    Status,
    SetVars,
    Service
}

struct Args {
    op: Option<Op>,
    bcast: IpAddr,
    count: usize,
    mac: Option<String>,
    ip: Option<IpAddr>,
    key: Option<String>,
    vars: Vec<(String, Value)>
}

fn parse_var(v: &str) -> Vec<(String, Value)> {
    v.split(',').map(|kv| -> Option<(String, Value)> {
        let mut sp = kv.split('=');
        let name = sp.next()?;
        let value = sp.next()?;
        let value = Value::from_str(value).ok()?;
        Some((name.to_owned(), value))
    }).map(|kvo| kvo.expect("invalid KV"))
    .collect()
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
            vars: vec![],
        }
    }
}

fn help() {
    let a = Args::default();
    println!(r#"
Gree Command Line Interface

Usage

async_tool --scan|-s [ --bcast|-a <broadcast-addr({bcast})> ] [ --count|-c <max-devices({count})> ]
async_tool --bind|-b --ip|-i <device-ip-address> --mac|-m <device-mac-adress>
async_tool --status|-t --ip|-i <device-ip-address> --mac|-m <device-mac-adress> --key|-k <device-key>
async_tool --set|-e --ip|-i <device-ip-address> --mac|-m <device-mac-adress> --key|-k <device-key> --var|-v NAME=VALUE[,...]
async_tool --service|-S  [ --bcast|-a <broadcast-addr({bcast})> ] [ --count|-c <max-devices({count})> ]
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
                "--var" | "-v" => args.vars.append(&mut parse_var(&a)),
                other => panic!("`{other}` invalid")
            }
            None
        } else {
            match a.as_ref() {
                "--help" | "-h" => args.op = Some(Op::Help),
                "--bind" | "-b" => args.op = Some(Op::Bind),
                "--scan" | "-s" => args.op = Some(Op::Scan),
                "--status" | "-t" => args.op = Some(Op::Status),
                "--set" | "-e" => args.op = Some(Op::SetVars),
                "--service" | "-S" => args.op = Some(Op::Service),
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

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    info!("starting up");

    let args = getcmdln();

    let c = GreeClient::new().await?;

    match args.op {
        Some(Op::Scan) => {
            let devs = c.scan(args.bcast, args.count).await?;
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
            let r = c.bind(ip, &mac).await?;
            println!("{r:?}");
        }
        Some(Op::Status) => {
            let ip = args.ip.expect("Must specify --ip");
            let mac = args.mac.expect("Must specify --mac");
            let key = args.key.expect("Must specify --key");
            let r = c.status(ip, &mac, &key, &DEFAULT_VARS).await?;
            println!("{r:?}");            
        }
        Some(Op::SetVars) => {
            let ip = args.ip.expect("Must specify --ip");
            let mac = args.mac.expect("Must specify --mac");
            let key = args.key.expect("Must specify --key");

            if args.vars.is_empty() {
                panic!("must specify at least one variable")
            }
            let names: Vec<&'static str> = args.vars.iter().map(|(n, _)| vars::name_of(n).expect("invalid var name")).collect();
            let values: Vec<Value> = args.vars.into_iter().map(|(_, v)|v).collect();
            let r = c.setvars(ip, &mac, &key, &names, &values).await?;
            println!("{r:?}");            
        }
        Some(Op::Service) => {
            let port = 7777;
            let addr = [127, 0, 0, 1];
            let hello = warp::path!("hello" / String)
                .map(|name| format!("Hello, {}!", name));
            warp::serve(hello)
                .run((addr, port))
                .await;
        }
        Some(Op::Help) | None => {
            help()
        }
    }

    Ok(())
}