use log::{info, trace};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct ArpControlSettings {
    burst_window: Duration,
    max_burst: u32,
    normal_window: Duration,
    max_normal: u32,
    cleanup_threshold: usize,
    max_entries: usize,
}

impl Default for ArpControlSettings {
    fn default() -> Self {
        Self {
            burst_window: Duration::from_millis(200),
            max_burst: 12,
            normal_window: Duration::from_millis(500),
            max_normal: 24,
            cleanup_threshold: 1500,
            max_entries: 7500,
        }
    }
}

struct ArpControllerInner {
    settings: ArpControlSettings,
    burst_count: HashMap<(IpAddr, IpAddr), (Instant, u32)>,
    normal_count: HashMap<(IpAddr, IpAddr), (Instant, u32)>,
}

pub struct ArpController {
    inner: Arc<Mutex<ArpControllerInner>>,
}

impl ArpController {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ArpControllerInner {
                settings: ArpControlSettings::default(),
                burst_count: HashMap::new(),
                normal_count: HashMap::new(),
            })),
        }
    }

    pub async fn should_process(&self, src_ip: IpAddr, dst_ip: IpAddr) -> bool {
        let mut inner = self.inner.lock().await;
        let now = Instant::now();
        let pair = (src_ip, dst_ip);
        let settings = inner.settings.clone(); // Clone the settings

        // エントリ数ベースのクリーンアップ
        if inner.normal_count.len() >= settings.cleanup_threshold {
            inner.cleanup();
        }

        // キャパシティ制御
        if inner.normal_count.len() >= settings.max_entries {
            info!("ARPエントリ数が最大値を超えました");
            return false;
        }

        // バースト制御
        {
            let entry = inner.burst_count.entry(pair).or_insert((now, 0));
            if now.duration_since(entry.0) < settings.burst_window {
                entry.1 += 1;
                if entry.1 >= settings.max_burst {
                    info!("ARPバースト制限超過: src={}, dst={}", src_ip, dst_ip);
                    return false;
                }
            } else {
                *entry = (now, 1);
            }
        }

        // 通常レート制御
        {
            let entry = inner.normal_count.entry(pair).or_insert((now, 0));
            if now.duration_since(entry.0) < settings.normal_window {
                entry.1 += 1;
                if entry.1 >= settings.max_normal {
                    info!("ARP通常レート制限超過: src={}, dst={}", src_ip, dst_ip);
                    return false;
                }
            } else {
                *entry = (now, 1);
            }
        }

        trace!("ARP処理: src={}, dst={}", src_ip, dst_ip);
        true
    }
}

impl ArpControllerInner {
    fn cleanup(&mut self) {
        let now = Instant::now();
        let settings = self.settings.clone();

        // 期限切れのエントリを削除
        self.burst_count
            .retain(|_, (time, _)| now.duration_since(*time) < settings.burst_window);

        self.normal_count
            .retain(|_, (time, _)| now.duration_since(*time) < settings.normal_window);

        // 古いエントリを削除してキャパシティを確保
        if self.normal_count.len() > settings.max_entries / 2 {
            let mut entries: Vec<_> = self
                .normal_count
                .iter()
                .map(|(k, (t, c))| (k.clone(), *t, *c))
                .collect();

            entries.sort_by(|a, b| b.1.cmp(&a.1));

            self.normal_count.clear();
            for (k, t, c) in entries.into_iter().take(settings.max_entries / 2) {
                self.normal_count.insert(k, (t, c));
            }
        }

        info!(
            "ARPコントローラーのクリーンアップを実行: アクティブペア={}",
            self.normal_count.len()
        );
    }
}
