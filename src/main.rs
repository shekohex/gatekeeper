use esp_idf_svc::hal::gpio::*;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::hal::task::*;
use esp_idf_svc::hal::timer::*;

fn main() -> anyhow::Result<()> {
    // It is necessary to call this function once. Otherwise some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71
    esp_idf_svc::sys::link_patches();

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    let peripherals = Peripherals::take()?;
    let mut led = PinDriver::output(peripherals.pins.gpio2)?;
    let mut timer = TimerDriver::new(peripherals.timer00, &TimerConfig::new())?;

    log::info!("Running blinking example!");

    block_on(async move { blinky(&mut led, &mut timer).await })?;

    Ok(())
}

async fn blinky<T: Pin, Mode: OutputMode>(
    led: &mut PinDriver<'_, T, Mode>,
    timer: &mut TimerDriver<'_>,
) -> anyhow::Result<()> {
    loop {
        led.set_high()?;

        timer.delay(timer.tick_hz()).await?;

        led.set_low()?;

        timer.delay(timer.tick_hz()).await?;
    }
}
