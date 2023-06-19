use gree::{*, sync_client::*, vars::*};
use log::info;
use std::{net::{IpAddr, Ipv4Addr, SocketAddr}, str::FromStr};

const BCAST_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255));

enum Op {
    Help,
    Scan,
    Bind,
    Get,
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
    names: Vec<VarName>,
    vars: Vec<(VarName, Value)>
}

fn parse_names(v: &str) -> Vec<VarName> {
    v.split(',').map(|name| vars::name_of(name).expect("Invalid variable name")).collect()
}

fn parse_vars(v: &str) -> Vec<(VarName, Value)> {
    v.split(',').map(|kv| -> Option<(VarName, Value)> {
        let mut sp = kv.split('=');
        let name = sp.next()?;
        let name = vars::name_of(name).expect("Invalid variable name");
        let value = sp.next()?;
        let value = Value::from_str(value).ok()?;
        Some((name, value))
    }).map(|kvo| kvo.expect("invalid variable=value pair(s)"))
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
            names: vec![POW, MOD, SET_TEM, TEM_UN, WD_SPD],
            vars: vec![],
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
sync_tool --get|-g --ip|-i <device-ip-address> --mac|-m <device-mac-adress> --key|-k <device-key> --name|-n NAME[,...]
sync_tool --set|-e --ip|-i <device-ip-address> --mac|-m <device-mac-adress> --key|-k <device-key> --var|-v NAME=VALUE[,...]
sync_tool --service|-S  [ --bcast|-a <broadcast-addr({bcast})> ] [ --count|-c <max-devices({count})> ]
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
                "--name" | "-n" => args.names.append(&mut parse_names(&a)),
                "--var" | "-v" => args.vars.append(&mut parse_vars(&a)),
                other => panic!("`{other}` invalid")
            }
            None
        } else {
            match a.as_ref() {
                "--help" | "-h" => args.op = Some(Op::Help),
                "--bind" | "-b" => args.op = Some(Op::Bind),
                "--scan" | "-s" => args.op = Some(Op::Scan),
                "--get" | "-g" => args.op = Some(Op::Get),
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


fn main() -> Result<()> {
    env_logger::init();
    info!("starting up");

    let args = getcmdln();

    let mut cc = GreeClientConfig::default();
    cc.bcast_addr = args.bcast;
    cc.max_count = args.count;
    //cc.bind_addr = "10.0.0.101:0".parse().unwrap();

    let c = GreeClient::new(cc)?;

    log::trace!("Init ok");

    match args.op {
        Some(Op::Scan) => {
            let devs = c.scan()?;
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
        Some(Op::Get) => {
            let ip = args.ip.expect("Must specify --ip");
            let mac = args.mac.expect("Must specify --mac");
            let key = args.key.expect("Must specify --key");
            let r = c.getvars(ip, &mac, &key, &args.names)?;
            println!("{r:?}");            
        }
        Some(Op::SetVars) => {
            let ip = args.ip.expect("Must specify --ip");
            let mac = args.mac.expect("Must specify --mac");
            let key = args.key.expect("Must specify --key");

            if args.vars.is_empty() {
                panic!("must specify at least one variable")
            }
            let names: Vec<VarName> = args.vars.iter().map(|(n, _)| *n).collect();
            let values: Vec<Value> = args.vars.into_iter().map(|(_, v)|v).collect();
            let r = c.setvars(ip, &mac, &key, &names, &values)?;
            println!("{r:?}");            
        }
        Some(Op::Service) => {
            service(args)?
        }
        Some(Op::Help) | None => {
            help()
        }
    }

    Ok(())
}

/// Example usage
/// 
/// ```bash
/// curl http://localhost:7777/scan
/// curl http://localhost:7777/dev/000cc0000000/get?SetTem&Pow
/// curl http://localhost:7777/dev/000cc0000000/set?SetTem=23&Pow=1
/// ```
/// 
fn service(args: Args) -> Result<()> {
    use tiny_http::{Server, Response};

    let port: u16 = 7777;
    let addr: [u8; 4] = [127, 0, 0, 1];
    let sa: SocketAddr = (addr, port).into();

    let server = Server::http(sa).unwrap();

    let mut gree_cfg = GreeConfig::default();
    gree_cfg.client_config.bcast_addr = args.bcast;
    gree_cfg.client_config.max_count = args.count;

    let mut gree = Gree::new(gree_cfg)?;
    enum Req<'t> {
        Scan,
        Get(&'t str, Vec<&'t str>),
        Set(&'t str, Vec<(&'t str, &'t str)>)
    }
    fn parse_request_uri<'t>(uri: &'t str) -> Option<Req<'t>> {
        let mut qi = uri.splitn(2, '?');
        let path = qi.next()?;
        let query = qi.next();

        let mut qp = path.split('/').skip(1);
        let root = qp.next()?;
        match root {
            "scan" => Some(Req::Scan),
            "dev" => {
                let device = qp.next()?;
                let verb = qp.next()?;
                match verb {
                    "get" => {
                        Some(Req::Get(device, query?.split('&').collect()))
                    }
                    "set" => {
                        let kv: Option<Vec<(&'t str, &'t str)>> = query?.split('&').map(|kv|kv.splitn(2, '=')).map(|mut i| {
                            let k = i.next()?;
                            let v = i.next()?;
                            Some((k, v))
                        }).collect();
                        Some(Req::Set(device, kv?))
                    }
                    _ => None
                }
            }
            _ => None
        }
    }
    
    fn make_response(gree: &mut Gree, op: Option<Req>) -> Result<Response<std::io::Cursor<Vec<u8>>>> {
        Ok(match op {
            Some(Req::Scan) => {
                gree.scan()?;
                Response::from_string("{}")
            }
            Some(Req::Get(device, names)) => {
                let mut nvb = net_var_bag_from_names(names.iter())?;
                gree.net_read(device, &mut nvb)?;
                let json = net_var_bag_to_json(&nvb);
                Response::from_string(serde_json::to_string(&json)?)
            }
            Some(Req::Set(device, nvs)) => {
                let mut nvb = net_var_bag_from_nvs(nvs.iter().map(|(k, v)| (k, v) ))?;
                gree.net_write(device, &mut nvb)?;
                let json = net_var_bag_to_json(&nvb);
                Response::from_string(serde_json::to_string(&json)?)
            }
            _ => Response::from_string("invalid request").with_status_code(400)
        })       
    }

    for request in server.incoming_requests() {
        info!("received request! method: {:?}, url: {:?}, headers: {:?}",
            request.method(),
            request.url(),
            request.headers()
        );

        let response = match make_response(&mut gree, parse_request_uri(request.url())) {
            Ok(r) => r,
            Err(e) => {
                let code = match &e {
                    Error::Io(_) | Error::ResponseTimeout | Error::RecvTimeout => 503,
                    Error::NotFound(_) => 404,
                    _ => 400
                };
                Response::from_string(format!("error: {e}")).with_status_code(code)
            }
        };
        request.respond(response)?;
    }

    Ok(())
}