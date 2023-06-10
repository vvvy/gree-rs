use gree::{*, async_client::*};
use log::info;
use serde_derive::Serialize;
use std::{net::{IpAddr, Ipv4Addr}, str::FromStr, convert::Infallible};
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
            async_service(args).await?;
        }
        Some(Op::Help) | None => {
            help()
        }
    }

    Ok(())
}


async fn async_service(args: Args) -> Result<()> {
    use tokio::sync::Mutex;
    use std::sync::Arc;
    use warp as w;

    type HMSS = std::collections::HashMap<String,String>;

    let port = 7777;
    let addr = [127, 0, 0, 1];

    let mut gree_cfg = GreeConfig::default();
    gree_cfg.bcast_addr = args.bcast;
    gree_cfg.max_count = args.count;

    let gree = Gree::from_config(gree_cfg).await?;
    let gree = Arc::new(Mutex::new(gree));

    fn with_gree(gree: &Arc<Mutex<Gree>>) -> impl Filter<Extract = (Arc<Mutex<Gree>>,), Error = std::convert::Infallible> + Clone {
        let gree = gree.clone();
        w::any().map(move || gree.clone())
    }

    #[derive(Debug)]
    struct E { e: Error }
    impl w::reject::Reject for E { }
    impl E {
        fn custom(e: Error) -> w::reject::Rejection {
            w::reject::custom(E { e })
        }

        async fn handle_rejection(err: w::Rejection) -> std::result::Result<impl w::Reply, Infallible> {
            use warp::hyper::StatusCode;
        
            let (code, message) = if let Some(e) = err.find::<E>() {
                let code = match &e.e {
                    Error::NotFound(_) => StatusCode::NOT_FOUND,
                    Error::Io(_) | Error::ResponseTimeout | Error::RecvTimeout => StatusCode::SERVICE_UNAVAILABLE,
                    _ => StatusCode::BAD_REQUEST
                };
                (code, format!("{}", &e.e))
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, "UNKNOWN REJECTION".to_owned())
            };
        
            /// An API error serializable to JSON.
            #[derive(Serialize)]
            struct ErrorMessage {
                code: u16,
                message: String,
            }
        
            let json = warp::reply::json(&ErrorMessage {
                code: code.into(),
                message,
            });
            Ok(warp::reply::with_status(json, code))
        }
    }

    #[derive(Serialize)]
    struct DevInfo { mac: String, ip: String  }

    let scan = w::path!("scan")
        .and(with_gree(&gree))
        .and_then(|gree: Arc<Mutex<Gree>>| async move { 
            gree
            .lock().await
            .scan().await
            .map(|_| w::reply::reply())
            .map_err(E::custom)
        });
    let population = w::path!("dev")
        .and(with_gree(&gree))
        .and_then(|gree: Arc<Mutex<Gree>>| async move { 
            let devnames: Vec<String> = gree.lock().await.state().devices.keys().map(|w|w.to_owned()).collect();
            let rv: std::result::Result<_, w::Rejection> = Ok(w::reply::json(&devnames));
            rv
        });
    let devinfo = w::path!("dev" / String)
        .and(with_gree(&gree))
        .and_then(|dev, gree: Arc<Mutex<Gree>>| async move { 
            gree
            .lock().await
            .with_device(&dev, |dev| DevInfo { mac: dev.scan_result.mac.clone(), ip: dev.ip.to_string() })
            .map(|d| w::reply::json(&d))
            .map_err(E::custom)
        });
    let get = w::path!("dev" / String / "get")
        .and(w::query::<HMSS>())
        .and(with_gree(&gree))
        .and_then(|dev: String, vars: HMSS, gree: Arc<Mutex<Gree>>| async move { 
            let mut bag = net_var_bag_from_names(vars.keys()).map_err(|e| E { e })?;
            gree
            .lock().await
            .net_read(&dev, &mut bag).await
            .map(|_| w::reply::json(&net_var_bag_to_json(&bag)))
            .map_err(E::custom)
        });
    let set = w::path!("dev" / String / "set")
        .and(w::query::<HMSS>())
        .and(with_gree(&gree))
        .and_then(|dev, vars: HMSS, gree: Arc<Mutex<Gree>>| async move {
            let mut bag = net_var_bag_from_nvs(vars).map_err(|e| E { e })?;
            gree
            .lock().await
            .net_write(&dev, &mut bag).await
            .map(|_| w::reply::json(&net_var_bag_to_json(&bag)))
            .map_err(E::custom)
        });
    w::serve(scan.or(population).or(devinfo).or(set).or(get).recover(E::handle_rejection))
        .run((addr, port))
        .await;

    Ok(())
}

