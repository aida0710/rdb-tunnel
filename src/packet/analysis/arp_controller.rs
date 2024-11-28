use crate::packet::MacAddr;
use log::{debug, info, trace};
use std::collections::HashMap;
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
            burst_window: Duration::from_millis(100),   // 100ミリ秒に短縮
            max_burst: 8,                               // バーストを8パケットに制限
            normal_window: Duration::from_millis(1000), // 1秒に延長
            max_normal: 16,                             // 通常レートも16パケットに制限
            cleanup_threshold: 1500,                    // 現状維持
            max_entries: 7500,                          // 現状維持
        }
    }
}

struct ArpControllerInner {
    settings: ArpControlSettings,
    // (送信元MAC, 送信先MAC)のペアでカウント
    burst_count: HashMap<(MacAddr, MacAddr), (Instant, u32)>,
    normal_count: HashMap<(MacAddr, MacAddr), (Instant, u32)>,
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

    pub async fn should_process(&self, src_mac: MacAddr, dst_mac: MacAddr) -> bool {
        let mut inner = self.inner.lock().await;
        let now = Instant::now();
        let pair = (src_mac.clone(), dst_mac.clone());
        let settings = inner.settings.clone();

        // エントリ数ベースのクリーンアップ
        if inner.normal_count.len() >= settings.cleanup_threshold {
            inner.cleanup();
        }

        // キャパシティ制御
        if inner.normal_count.len() >= settings.max_entries {
            info!("ARPエントリ数が最大値を超えました");
            return false;
        }

        // MACペアごとのバースト制御
        {
            let entry = inner.burst_count.entry(pair.clone()).or_insert((now, 0));
            if now.duration_since(entry.0) < settings.burst_window {
                entry.1 += 1;
                if entry.1 >= settings.max_burst {
                    debug!("ARPバースト制限超過: src_mac={}, dst_mac={}", src_mac, dst_mac);
                    return false;
                }
            } else {
                *entry = (now, 1);
            }
        }

        // MACペアごとの通常レート制御
        {
            let entry = inner.normal_count.entry(pair).or_insert((now, 0));
            if now.duration_since(entry.0) < settings.normal_window {
                entry.1 += 1;
                if entry.1 >= settings.max_normal {
                    debug!("ARP通常レート制限超過: src_mac={}, dst_mac={}", src_mac, dst_mac);
                    return false;
                }
            } else {
                *entry = (now, 1);
            }
        }

        trace!("ARP処理: src_mac={}, dst_mac={}", src_mac, dst_mac);
        true
    }
}

impl ArpControllerInner {
    fn cleanup(&mut self) {
        let now = Instant::now();
        let settings = self.settings.clone();

        // 期限切れのエントリを削除
        self.burst_count.retain(|_, (time, _)| now.duration_since(*time) < settings.burst_window);
        self.normal_count.retain(|_, (time, _)| now.duration_since(*time) < settings.normal_window);

        // 古いエントリを削除してキャパシティを確保
        if self.normal_count.len() > settings.max_entries / 2 {
            let mut entries: Vec<_> = self.normal_count.iter().map(|(k, (t, c))| (k.clone(), *t, *c)).collect();

            entries.sort_by(|a, b| b.1.cmp(&a.1));

            self.normal_count.clear();
            for (k, t, c) in entries.into_iter().take(settings.max_entries / 2) {
                self.normal_count.insert(k, (t, c));
            }
        }

        info!("ARPコントローラーのクリーンアップを実行: アクティブペア={}", self.normal_count.len());
    }
}
