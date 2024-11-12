pub fn measure_time<F, R>(process_name: &str, f: F) -> R
where
    F: FnOnce() -> R,
{
    use std::time::Instant;

    let start_time = Instant::now();
    let result = f();
    let end_time = Instant::now();

    let duration = end_time.duration_since(start_time);
    let nanos = duration.as_nanos();

    // ナノ秒を適切な単位に変換
    let (time_str, unit) = if nanos < 1_000 {
        (nanos as f64, "ns")
    } else if nanos < 1_000_000 {
        (nanos as f64 / 1_000.0, "µs")
    } else if nanos < 1_000_000_000 {
        (nanos as f64 / 1_000_000.0, "ms")
    } else {
        (nanos as f64 / 1_000_000_000.0, "s")
    };

    println!("{} の処理時間: {:.6} {}", process_name, time_str, unit);

    result
}