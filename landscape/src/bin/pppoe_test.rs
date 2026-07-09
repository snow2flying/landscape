use landscape_common::service::ServiceStatus;
use landscape_common::service::WatchService;
use pnet::datalink::NetworkInterface;
use std::env;
use std::time::Duration;
use tokio::sync::oneshot;

#[derive(Clone, Debug)]
pub struct CmdArgs {
    ifindex: Option<u32>,
    iface_name: Option<String>,
    username: String,
    pass: String,
    mtu: u16,
    timeout_secs: u64,
}

fn print_help(program: &str) {
    println!(
        "Usage: {program} [OPTIONS]\n\nOptions:\n  -i, --ifindex <IFINDEX>\n      --iface-name <IFACE_NAME>\n  -u, --username <USERNAME>          [default: user]\n  -p, --pass <PASS>                  [default: pass]\n      --mtu <MTU>                    [default: 1492]\n      --timeout-secs <TIMEOUT_SECS>  [default: 30]\n  -h, --help                         Print help"
    );
}

fn parse_args() -> Result<CmdArgs, String> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "pppoe_test".to_string());

    let mut params = CmdArgs {
        ifindex: None,
        iface_name: None,
        username: "user".to_string(),
        pass: "pass".to_string(),
        mtu: 1492,
        timeout_secs: 30,
    };

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help(&program);
                std::process::exit(0);
            }
            "-i" | "--ifindex" => {
                let value = args.next().ok_or_else(|| format!("missing value for {arg}"))?;
                params.ifindex =
                    Some(value.parse::<u32>().map_err(|_| format!("invalid ifindex: {value}"))?);
            }
            "--iface-name" => {
                params.iface_name =
                    Some(args.next().ok_or_else(|| "missing value for --iface-name".to_string())?);
            }
            "-u" | "--username" => {
                params.username = args.next().ok_or_else(|| format!("missing value for {arg}"))?;
            }
            "-p" | "--pass" => {
                params.pass = args.next().ok_or_else(|| format!("missing value for {arg}"))?;
            }
            "--mtu" => {
                let value = args.next().ok_or_else(|| "missing value for --mtu".to_string())?;
                params.mtu = value.parse::<u16>().map_err(|_| format!("invalid mtu: {value}"))?;
            }
            "--timeout-secs" => {
                let value =
                    args.next().ok_or_else(|| "missing value for --timeout-secs".to_string())?;
                params.timeout_secs =
                    value.parse::<u64>().map_err(|_| format!("invalid timeout: {value}"))?;
            }
            unknown => return Err(format!("unexpected argument '{unknown}' found")),
        }
    }

    Ok(params)
}

fn resolve_interface(params: &CmdArgs) -> Option<NetworkInterface> {
    let all_interfaces = pnet::datalink::interfaces();
    if let Some(iface_name) = &params.iface_name {
        return all_interfaces.into_iter().find(|iface| iface.name == *iface_name);
    }

    if let Some(ifindex) = params.ifindex {
        return all_interfaces.into_iter().find(|iface| iface.index == ifindex);
    }

    None
}

// tcpdump -vv -i ens6 ether proto 0x8863 or ether proto 0x8864
// cargo run --package landscape --bin pppoe_test
// cargo build --package landscape --bin pppoe_test --target aarch64-unknown-linux-gnu
#[tokio::main]
async fn main() {
    let program = env::args().next().unwrap_or_else(|| "pppoe_test".to_string());
    let params = match parse_args() {
        Ok(params) => params,
        Err(err) => {
            eprintln!("error: {err}\n");
            print_help(&program);
            std::process::exit(2);
        }
    };
    let service_status = WatchService::new();
    let Some(interface) = resolve_interface(&params) else {
        eprintln!("未找到目标接口，请传入 --iface-name 或 --ifindex");
        std::process::exit(2);
    };

    let Some(interface_mac) = interface.mac else {
        eprintln!("接口 {} 没有 MAC 地址", interface.name);
        std::process::exit(2);
    };

    let iface_name = interface.name.clone();
    let iface_index = interface.index;
    let iface_mac = interface_mac.octets().into();

    println!(
        "开始测试 PPPoE，iface={} ifindex={} mtu={} timeout={}s",
        iface_name, iface_index, params.mtu, params.timeout_secs
    );

    let (notice, notice_rx) = oneshot::channel();
    let service_status_clone = service_status.clone();
    let username = params.username.clone();
    let password = params.pass.clone();
    tokio::spawn(async move {
        landscape::pppoe_client::create_pppoe_client(
            landscape::pppoe_client::PPPoEClientConfig::new(
                iface_index,
                iface_name,
                iface_mac,
                username,
                password,
                true,
                params.mtu,
                None,
            ),
            service_status_clone,
            None,
        )
        .await;

        if let Err(e) = notice.send(()) {
            println!("发送错误: {e:?}");
        }
    });

    let mut exit_code = 1;
    let mut status_rx = service_status.subscribe();
    let timeout = tokio::time::sleep(Duration::from_secs(params.timeout_secs));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("收到 Ctrl-C，开始断连");
                if !service_status.is_exit() {
                    service_status.just_change_status(ServiceStatus::Stopping);
                }
                exit_code = 130;
                break;
            }
            _ = &mut timeout => {
                println!("等待 PPPoE 连接超时");
                if !service_status.is_exit() {
                    service_status.just_change_status(ServiceStatus::Stopping);
                }
                exit_code = 124;
                break;
            }
            change_result = status_rx.changed() => {
                if change_result.is_err() {
                    println!("状态通道关闭");
                    break;
                }

                let current_status = status_rx.borrow().clone();
                println!("PPPoE 状态变更: {current_status:?}");
                match current_status {
                    ServiceStatus::Running => {
                        std::process::exit(0);
                    }
                    ServiceStatus::Failed => {
                        exit_code = 1;
                        break;
                    }
                    ServiceStatus::Stop => {
                        break;
                    }
                    ServiceStatus::Staring | ServiceStatus::Stopping => {}
                }
            }
        }
    }

    if let Err(e) = notice_rx.await {
        println!("等待过程出错: {e:?}");
        if exit_code == 0 {
            exit_code = 1;
        }
    }

    let final_status = service_status.0.borrow().clone();
    println!("测试结束，最终状态: {final_status:?}");
    if matches!(final_status, ServiceStatus::Failed) && exit_code == 0 {
        exit_code = 1;
    }
    std::process::exit(exit_code);
}
