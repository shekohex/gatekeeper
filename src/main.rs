use core::str::FromStr;
use std::net::Ipv4Addr;

use esp_idf_svc::eventloop::*;
use esp_idf_svc::hal::gpio::*;
use esp_idf_svc::hal::peripherals::*;
use esp_idf_svc::hal::reset;
use esp_idf_svc::hal::task::*;
use esp_idf_svc::hal::timer::*;
use esp_idf_svc::ipv4;
use esp_idf_svc::netif::*;
use esp_idf_svc::nvs::*;
use esp_idf_svc::sntp::*;
use esp_idf_svc::timer::*;
use esp_idf_svc::wifi::*;

// WIFI credentials
const SSID: &str = env!("WIFI_SSID");
const PASSWORD: &str = env!("WIFI_PASS");
// Expects IPv4 address
const DEVICE_IP: &str = env!("DEVICE_IP");
// Expects IPv4 address
const GATEWAY_IP: &str = env!("GATEWAY_IP");
// Expects a number between 0 and 32, defaults to 24
const GATEWAY_NETMASK: Option<&str> = option_env!("GATEWAY_NETMASK");
// Expects a string for TZ database, defaults to UTC
// see: https://docs.rs/chrono-tz/0.9.0/chrono_tz/enum.Tz.html
const TIMEZONE: Option<&str> = option_env!("TIMEZONE");

// If the SSID is Wokwi-GUEST, it will connect without a password
// Useful for the Wokwi simulator
// see: https://docs.wokwi.com/guides/esp32-wifi
const WOKWI_GUEST: &str = "Wokwi-GUEST";

fn main() -> anyhow::Result<()> {
    // It is necessary to call this function once. Otherwise some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71
    esp_idf_svc::sys::link_patches();

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    let peripherals = Peripherals::take()?;
    let sys_loop = EspSystemEventLoop::take()?;
    let timer_service = EspTaskTimerService::new()?;
    let nvs = EspDefaultNvsPartition::take()?;

    let mut led = PinDriver::output(peripherals.pins.gpio2)?;
    let mut timer = TimerDriver::new(peripherals.timer00, &TimerConfig::new())?;

    log::info!("Configuring Wifi..");
    let wifi = WifiDriver::new(peripherals.modem, sys_loop.clone(), Some(nvs))?;
    let wifi = configure_wifi(wifi)?;

    let mut wifi = AsyncWifi::wrap(wifi, sys_loop, timer_service)?;

    block_on(async move {
        connect_wifi(&mut wifi).await?;

        let ip_info = wifi.wifi().sta_netif().get_ip_info()?;

        log::info!("Wifi Interface info: {:?}", ip_info);

        log::info!("Running the loop...");

        blinky(&mut led, &mut timer).await?;
        anyhow::Ok(())
    })?;

    // The main task should never return
    // if it does, we should restart the device
    reset::restart();

    Ok(())
}

async fn blinky<T: Pin, Mode: OutputMode>(
    led: &mut PinDriver<'_, T, Mode>,
    timer: &mut TimerDriver<'_>,
) -> anyhow::Result<()> {
    log::info!("Starting SNTP service...");
    let _sntp = EspSntp::new_default()?;
    let tz: chrono_tz::Tz = match TIMEZONE {
        Some(s) => s.parse()?,
        None => chrono_tz::UTC,
    };

    log::info!("Current timezone: {tz}");
    loop {
        led.set_high()?;
        let now = chrono::Utc::now().with_timezone(&tz);
        log::info!("ON at: {now}");

        timer.delay(timer.tick_hz()).await?;

        led.set_low()?;

        let now = chrono::Utc::now().with_timezone(&tz);
        log::info!("OFF at: {now}");

        timer.delay(timer.tick_hz()).await?;
    }
}

fn configure_wifi(wifi: WifiDriver) -> anyhow::Result<EspWifi> {
    let netmask = GATEWAY_NETMASK.unwrap_or("24");
    let netmask = u8::from_str(netmask)?;
    let gateway_addr = Ipv4Addr::from_str(GATEWAY_IP)?;
    let static_ip = Ipv4Addr::from_str(DEVICE_IP)?;

    let mut wifi = EspWifi::wrap_all(
        wifi,
        EspNetif::new_with_conf(&NetifConfiguration {
            ip_configuration: ipv4::Configuration::Client(ipv4::ClientConfiguration::Fixed(
                ipv4::ClientSettings {
                    ip: static_ip,
                    subnet: ipv4::Subnet {
                        gateway: gateway_addr,
                        mask: ipv4::Mask(netmask),
                    },
                    // Cloudflare DNS
                    dns: Some(Ipv4Addr::from([1, 1, 1, 1])),
                    secondary_dns: Some(Ipv4Addr::from([1, 1, 0, 0])),
                },
            )),
            ..NetifConfiguration::wifi_default_client()
        })?,
        #[cfg(esp_idf_esp_wifi_softap_support)]
        EspNetif::new(NetifStack::Ap)?,
    )?;

    let wifi_configuration = Configuration::Client(ClientConfiguration {
        ssid: SSID.try_into().unwrap(),
        bssid: None,
        auth_method: if SSID == WOKWI_GUEST {
            AuthMethod::None
        } else {
            AuthMethod::WPA2Personal
        },
        password: PASSWORD.try_into().unwrap(),
        channel: None,
    });
    wifi.set_configuration(&wifi_configuration)?;

    Ok(wifi)
}

async fn connect_wifi(wifi: &mut AsyncWifi<EspWifi<'static>>) -> anyhow::Result<()> {
    wifi.start().await?;
    log::info!("Wifi started");

    wifi.connect().await?;
    log::info!("Wifi connected");

    wifi.wait_netif_up().await?;
    log::info!("Wifi netif up");

    Ok(())
}
