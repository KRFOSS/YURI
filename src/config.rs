use anyhow::{Context, Result};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: String,
    pub upstream_base: String,
    pub cache_dir: String,
    pub max_cache_size_bytes: u64,
    pub default_ttl: Duration,
    pub eviction_policy: EvictionPolicy,
    pub cache_clear_cron: Option<String>, // "0" 또는 비설정이면 비활성화
    pub cache_clear_interval: Option<Duration>, // CACHE_CLEAR_INTERVAL_SECS (초) 0 또는 미설정 => 비활성화
}

#[derive(Debug, Clone, Copy)]
pub enum EvictionPolicy {
    /// First-In-First-Out (기존 created_at 기반)
    Fifo,
    /// Least Recently Used (last_access_at 오래된 것 먼저)
    Lru,
    /// Size 우선 (가장 큰 객체부터 제거)
    Size,
    /// LRU 우선, 동일/유사 접근시 큰 객체 우선 제거
    LruSize,
}

impl EvictionPolicy {
    pub fn from_env_var(s: &str) -> Self {
        match s.to_ascii_uppercase().as_str() {
            "FIFO" => Self::Fifo,
            "SIZE" => Self::Size,
            "LRU_SIZE" => Self::LruSize,
            _ => Self::Lru, // 기본 LRU
        }
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let listen_addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
        let upstream_base = std::env::var("UPSTREAM_BASE").context("UPSTREAM_BASE is required")?;
        let cache_dir = std::env::var("CACHE_DIR").unwrap_or_else(|_| "cache".into());
        let max_cache_size_bytes: u64 = std::env::var("MAX_CACHE_SIZE_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5 * 1024 * 1024 * 1024); // 5GB default
        let default_ttl_secs: u64 = std::env::var("DEFAULT_TTL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300);
        let eviction_policy = std::env::var("EVICTION_POLICY").unwrap_or_else(|_| "LRU".into());
        let cache_clear_cron_raw = std::env::var("CACHE_CLEAR_CRON").ok();
        let cache_clear_cron = cache_clear_cron_raw.and_then(|v| {
            let trimmed = v.trim();
            if trimmed.is_empty() || trimmed == "0" {
                None
            } else {
                Some(trimmed.to_string())
            }
        });
        // 초 단위 주기적 전체 클리어 설정 (cron 보다 단순). 0 또는 음수/파싱 실패 => 비활성화
        let cache_clear_interval = std::env::var("CACHE_CLEAR_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .and_then(|secs| {
                if secs == 0 {
                    None
                } else {
                    Some(Duration::from_secs(secs))
                }
            });
        Ok(Self {
            listen_addr,
            upstream_base,
            cache_dir,
            max_cache_size_bytes,
            default_ttl: Duration::from_secs(default_ttl_secs),
            eviction_policy: EvictionPolicy::from_env_var(&eviction_policy),
            cache_clear_cron,
            cache_clear_interval,
        })
    }
}
