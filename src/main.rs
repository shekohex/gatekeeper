use core::str::FromStr;
use core::sync::atomic::{AtomicBool, Ordering};
use std::net::Ipv4Addr;
use parking_lot::RwLock;

use esp_idf_svc::eventloop::*;
use esp_idf_svc::hal::gpio::*;
use esp_idf_svc::hal::modem::Modem;
use esp_idf_svc::hal::peripherals::*;
use esp_idf_svc::hal::reset;
use esp_idf_svc::hal::task::*;
use esp_idf_svc::hal::timer::*;
use esp_idf_svc::http;
use esp_idf_svc::ipv4;
use esp_idf_svc::netif::*;
use esp_idf_svc::nvs::*;
use esp_idf_svc::timer::*;
use esp_idf_svc::wifi::*;

// WIFI AP credentials
const AP_SSID: &str = env!("WIFI_AP_SSID");
const AP_PASSWORD: &str = env!("WIFI_AP_PASS");
// Expects IPv4 address
const GATEWAY_IP: &str = env!("GATEWAY_IP");
// Expects a number between 0 and 32, defaults to 24
const GATEWAY_NETMASK: Option<&str> = option_env!("GATEWAY_NETMASK");
// Expects a number between 1 and 13, defaults to 11
const WIFI_CHANNEL: Option<&str> = option_env!("WIFI_AP_CHANNEL");

// Need lots of stack to parse JSON
const STACK_SIZE: usize = 10240;

/// AtomicBool to control the running state of the server
static RUNNING: AtomicBool = AtomicBool::new(true);

/// Holds the State of the Gatekeeper.
pub struct Gatekeeper {
    pub sys_loop: EspSystemEventLoop,
    pub on_chip_led: PinDriver<'static, Gpio2, Output>,
    pub timeer00: TimerDriver<'static>,
}

fn main() -> anyhow::Result<()> {
    // It is necessary to call this function once. Otherwise some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71
    esp_idf_svc::sys::link_patches();

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    let peripherals = Peripherals::take()?;
    let sys_loop = EspSystemEventLoop::take()?;
    let ap = configure_ap(peripherals.modem, sys_loop.clone())?;

    let led = PinDriver::output(peripherals.pins.gpio2)?;
    let timer = TimerDriver::new(peripherals.timer00, &TimerConfig::new())?;

    // Move the server task to another thread, and wait for it on the main thread.
    // This way, the main thread can be used for other tasks.
    block_on(async move {
        let mut wifi = start_ap(ap, &sys_loop).await?;

        let ip_info = wifi.wifi().ap_netif().get_ip_info()?;

        log::info!("Wifi AP Interface info: {:?}", ip_info);

        let gatekeeper = Gatekeeper {
            sys_loop,
            on_chip_led: led,
            timeer00: timer,
        };

        let state = RwLock::new(gatekeeper);

        let _http_server = start_http_server(state)?;

        wifi.wifi_wait(|_| Ok(RUNNING.load(Ordering::SeqCst)), None)
            .await?;
        anyhow::Ok(())
    })?;

    log::error!("Server task ended unexpectedly");
    // The server task should never return
    // if it does, we should restart the device
    reset::restart();

    Ok(())
}

fn configure_ap(modem: Modem, sys_loop: EspSystemEventLoop) -> anyhow::Result<EspWifi<'static>> {
    let nvs = EspDefaultNvsPartition::take()?;
    let wifi = WifiDriver::new(modem, sys_loop, Some(nvs))?;

    log::info!("Configuring Wifi AP..");
    let netmask = GATEWAY_NETMASK.map(u8::from_str).transpose()?.unwrap_or(24);
    let gateway_addr = Ipv4Addr::from_str(GATEWAY_IP)?;
    let wifi_channel = WIFI_CHANNEL.map(u8::from_str).transpose()?.unwrap_or(11);

    let mut wifi = EspWifi::wrap_all(
        wifi,
        EspNetif::new(NetifStack::Sta)?,
        #[cfg(esp_idf_esp_wifi_softap_support)]
        EspNetif::new_with_conf(&NetifConfiguration {
            ip_configuration: ipv4::Configuration::Router(ipv4::RouterConfiguration {
                subnet: ipv4::Subnet {
                    gateway: gateway_addr,
                    mask: ipv4::Mask(netmask),
                },
                dhcp_enabled: true,
                dns: Some(Ipv4Addr::from([1, 1, 1, 1])),
                secondary_dns: Some(Ipv4Addr::from([1, 1, 0, 0])),
            }),
            ..NetifConfiguration::wifi_default_router()
        })?,
    )?;

    let wifi_configuration = Configuration::AccessPoint(AccessPointConfiguration {
        ssid: AP_SSID.try_into().unwrap(),
        ssid_hidden: false,
        auth_method: AuthMethod::WPA2Personal,
        password: AP_PASSWORD.try_into().unwrap(),
        channel: wifi_channel,
        secondary_channel: None,
        max_connections: 10,
        ..Default::default()
    });
    wifi.set_configuration(&wifi_configuration)?;
    Ok(wifi)
}

/// Starts the Wi-Fi Access Point.
async fn start_ap(
    ap: EspWifi<'static>,
    sys_loop: &EspSystemEventLoop,
) -> anyhow::Result<AsyncWifi<EspWifi<'static>>> {
    let timer_service = EspTaskTimerService::new()?;
    let mut wifi = AsyncWifi::wrap(ap, sys_loop.clone(), timer_service)?;
    wifi.start().await?;
    log::info!("Wifi AP started");

    wifi.wait_netif_up().await?;
    log::info!("Wifi AP netif up");

    log::info!("Created Wi-Fi with WIFI_SSID `{AP_SSID}` and WIFI_PASS `{AP_PASSWORD}`",);
    Ok(wifi)
}

fn start_http_server(
    gatekeeper: RwLock<Gatekeeper>,
) -> anyhow::Result<http::server::EspHttpServer<'static>> {
    use esp_idf_svc::http::Method;
    use esp_idf_svc::io::Write;

    let conf = http::server::Configuration {
        stack_size: STACK_SIZE,
        ..Default::default()
    };
    let mut server = http::server::EspHttpServer::new(&conf)?;
    server.fn_handler("/", Method::Get, |request| {
        request
            .into_ok_response()?
            .write_all(b"<html><body>Hello world!</body></html>")
    })?;

    server.fn_handler("/toggle", Method::Get, move |request| {
        let mut lock = gatekeeper.write();
        if lock.on_chip_led.is_set_high() {
            lock.on_chip_led.set_low()?;
        } else {
            lock.on_chip_led.set_high()?;
        }
        request.into_ok_response()?.flush()
    })?;
    Ok(server)
}
