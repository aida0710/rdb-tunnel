use std::future::Future;
use std::time::Instant;

pub async fn measure_time_async<Fut>(process_name: &str, console_output: bool, future: Fut) -> Fut::Output
where
    Fut: Future,
{
    let start_time = Instant::now();
    let result = future.await;
    let end_time = Instant::now();

    let duration = end_time.duration_since(start_time);
    let nanos = duration.as_nanos();

    let (time_str, unit) = if nanos < 1_000 {
        (nanos as f64, "ns")
    } else if nanos < 1_000_000 {
        (nanos as f64 / 1_000.0, "µs")
    } else if nanos < 1_000_000_000 {
        (nanos as f64 / 1_000_000.0, "ms")
    } else {
        (nanos as f64 / 1_000_000_000.0, "s")
    };

    if console_output {
        log::info!("{} の処理時間: {:.6} {}", process_name, time_str, unit);
    }

    result
}
