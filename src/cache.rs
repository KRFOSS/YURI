use anyhow::Result;
use blake3;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use tokio::{
    fs as tfs,
    io::AsyncWriteExt,
    sync::{mpsc, Mutex},
};
use tracing::{debug};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Meta {
    expires_at: u64,
    created_at: u64,
    size: u64,
    pub content_type: Option<String>,
    swr_expires_at: Option<u64>, // stale-while-revalidate 만료 시각 (expires_at 이후 추가 허용 구간)
    last_access_at: u64,         // LRU 용 (get 시 갱신)
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub bytes: Bytes,
    pub content_type: Option<String>,
    pub is_fresh: bool, // true: TTL 내, false: stale (swr 허용)
}

#[derive(Clone)]
pub struct DiskCache {
    root: PathBuf,
    max_size: u64,
    inner: Arc<Mutex<()>>, // simple global lock for size maintenance (can improve with sharded locks)
    default_ttl: Duration,
    // 정책: 구성 단계에서 선택
    policy: crate::config::EvictionPolicy,
    touch_tx: mpsc::Sender<PathBuf>, // 비동기 last_access_at 갱신 큐
}

impl DiskCache {
    pub async fn new<P: AsRef<Path>>(
        root: P,
        max_size: u64,
        default_ttl: Duration,
        policy: crate::config::EvictionPolicy,
    ) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        tfs::create_dir_all(&root).await?;
        let (tx, mut rx) = mpsc::channel::<PathBuf>(1024);
        let root_clone = root.clone();
        // 비동기 last_access_at 터치 워커
        tokio::spawn(async move {
            while let Some(meta_path) = rx.recv().await {
                // meta 파일 읽고 last_access_at 갱신 (best-effort)
                if let Ok(bytes) = tfs::read(&meta_path).await {
                    if let Ok(mut meta) = serde_json::from_slice::<Meta>(&bytes) {
                        meta.last_access_at = SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        if let Ok(new_bytes) = serde_json::to_vec(&meta) {
                            // write back (ignore errors)
                            if let Err(e) = Self::write_file(&meta_path, &new_bytes).await {
                                debug!(target: "cache", error=?e, path=?meta_path, "touch write failed");
                            }
                        }
                    } else {
                        // 손상된 meta → 관련 bin 제거
                        let base = meta_path.with_extension("");
                        let _ = tfs::remove_file(base.with_extension("bin")).await;
                        let _ = tfs::remove_file(&meta_path).await;
                        debug!(target: "cache", path=?meta_path, "removed corrupt meta");
                    }
                }
            }
            debug!(target: "cache", root=?root_clone, "touch worker stopped");
        });
        Ok(Self {
            root,
            max_size,
            inner: Arc::new(Mutex::new(())),
            default_ttl,
            policy,
            touch_tx: tx,
        })
    }

    /// 전체 캐시 비우기 (디렉토리 내 .bin / .meta / .vary 파일 삭제)
    pub async fn clear_all(&self) -> Result<()> {
        let mut stack = vec![self.root.clone()];
        while let Some(dir) = stack.pop() {
            let mut rd = tfs::read_dir(&dir).await?;
            while let Some(entry) = rd.next_entry().await? {
                let ty = entry.file_type().await?;
                if ty.is_dir() {
                    stack.push(entry.path());
                } else {
                    // 확장자 제한 없이 모두 제거 (캐시 용도로만 사용되는 디렉토리라 가정)
                    let _ = tfs::remove_file(entry.path()).await;
                }
            }
        }
        Ok(())
    }

    fn key_path(&self, key: &str) -> PathBuf {
        let mut hasher = blake3::Hasher::new();
        hasher.update(key.as_bytes());
        let hash = hasher.finalize().to_hex().to_string();
        let (a, b) = hash.split_at(2);
        self.root.join(a).join(b)
    }

    // Vary 인덱스 파일 경로 (.vary 확장자)
    fn vary_index_path(&self, base_key: &str) -> PathBuf {
        self.key_path(base_key).with_extension("vary")
    }

    async fn write_file(path: &Path, data: &[u8]) -> Result<()> {
        if let Some(parent) = path.parent() {
            tfs::create_dir_all(parent).await?;
        }
        let mut f = tfs::File::create(path).await?;
        f.write_all(data).await?;
        f.sync_all().await?;
        Ok(())
    }

    pub async fn get(&self, key: &str) -> Result<Option<CacheEntry>> {
        let path = self.key_path(key);
        let meta_path = path.with_extension("meta");
        let data_path = path.with_extension("bin");
        if !data_path.exists() || !meta_path.exists() {
            return Ok(None);
        }
        let meta_bytes = tfs::read(&meta_path).await.ok();
        let data_bytes = tfs::read(&data_path).await.ok();
        if let (Some(mb), Some(db)) = (meta_bytes, data_bytes) {
            if let Ok(meta) = serde_json::from_slice::<Meta>(&mb) {
                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if now > meta.expires_at {
                    // Fresh TTL 지난 후 swr window 확인 (stale 허용)
                    if let Some(swr_end) = meta.swr_expires_at {
                        if now <= swr_end {
                            // stale → touch (LRU 유지)
                            let _ = self.touch_tx.try_send(meta_path.clone());
                            return Ok(Some(CacheEntry {
                                bytes: Bytes::from(db),
                                content_type: meta.content_type,
                                is_fresh: false,
                            }));
                        }
                    }
                    // 완전 만료 → 파일 제거 (lazy cleanup)
                    let base = meta_path.with_extension("");
                    let _ = tfs::remove_file(base.with_extension("bin")).await;
                    let _ = tfs::remove_file(&meta_path).await;
                    debug!(target: "cache", key=%key, "expired entry removed");
                    return Ok(None);
                }
                // Fresh → 비동기 touch
                let _ = self.touch_tx.try_send(meta_path.clone());
                return Ok(Some(CacheEntry {
                    bytes: Bytes::from(db),
                    content_type: meta.content_type,
                    is_fresh: true,
                }));
            }
        }
        Ok(None)
    }

    pub async fn put(
        &self,
        key: &str,
        bytes: &[u8],
        content_type: Option<String>,
        ttl: Option<Duration>,
        swr: Option<Duration>,
    ) -> Result<()> {
        let _g = self.inner.lock().await; // ensure size ops consistent
        let path = self.key_path(key);
        let meta_path = path.with_extension("meta");
        let data_path = path.with_extension("bin");
        let size = bytes.len() as u64;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ttl_dur = ttl.unwrap_or(self.default_ttl);
        let meta = Meta {
            expires_at: now + ttl_dur.as_secs(),
            created_at: now,
            size,
            content_type,
            swr_expires_at: swr.map(|d| now + ttl_dur.as_secs() + d.as_secs()),
            last_access_at: now,
        };
        let meta_json = serde_json::to_vec(&meta)?;
        Self::write_file(&data_path, bytes).await?;
        Self::write_file(&meta_path, &meta_json).await?;
        self.enforce_size_limit().await?;
        Ok(())
    }

    async fn enforce_size_limit(&self) -> Result<()> {
        let mut entries: Vec<(PathBuf, u64, u64, u64)> = Vec::new(); // (base_path, created_at, size, last_access_at)
        let mut total = 0u64;
        let mut stack = vec![self.root.clone()];
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        while let Some(dir) = stack.pop() {
            let mut rd = tfs::read_dir(&dir).await?;
            while let Some(entry) = rd.next_entry().await? {
                let ty = entry.file_type().await?;
                if ty.is_dir() {
                    stack.push(entry.path());
                    continue;
                }
                if entry.path().extension().and_then(|s| s.to_str()) == Some("meta") {
                    let meta_bytes = tfs::read(entry.path()).await.ok();
                    if let Some(mb) = meta_bytes {
                        if let Ok(meta) = serde_json::from_slice::<Meta>(&mb) {
                            let base = entry.path().with_extension("");
                            let bin = base.with_extension("bin");
                            if bin.exists() {
                                // 만료( + swr 종료) 된 항목은 즉시 삭제 후 스킵
                                let fully_expired = if now > meta.expires_at {
                                    if let Some(swr_end) = meta.swr_expires_at { now > swr_end } else { true }
                                } else { false };
                                if fully_expired {
                                    let _ = tfs::remove_file(bin).await;
                                    let _ = tfs::remove_file(entry.path()).await;
                                    continue;
                                }
                                total += meta.size;
                                entries.push((
                                    base,
                                    meta.created_at,
                                    meta.size,
                                    meta.last_access_at,
                                ));
                            }
                        }
                    }
                }
            }
        }
        if total <= self.max_size {
            return Ok(());
        }
        debug!(target: "cache", current_bytes=total, max_bytes=self.max_size, entries=entries.len(), "starting eviction");
        // 정책별 정렬
        match self.policy {
            crate::config::EvictionPolicy::Fifo => {
                entries.sort_by_key(|(_, created, _, _)| *created);
            }
            crate::config::EvictionPolicy::Lru => {
                entries.sort_by_key(|(_, _created, _size, last_access)| *last_access);
            }
            crate::config::EvictionPolicy::Size => {
                entries.sort_by(|a, b| b.2.cmp(&a.2)); // 큰 것 먼저 제거
            }
            crate::config::EvictionPolicy::LruSize => {
                // last_access 오래된 것 우선, 동일 last_access 내에서는 큰 size 우선 제거
                entries.sort_by(|a, b| {
                    let la = a.3.cmp(&b.3); // last_access_at asc
                    if la == std::cmp::Ordering::Equal {
                        b.2.cmp(&a.2)
                    } else {
                        la
                    }
                });
            }
        }
        for (base, _created, size, _last_access) in entries {
            if total <= self.max_size {
                break;
            }
            let _ = tfs::remove_file(base.with_extension("bin")).await;
            let _ = tfs::remove_file(base.with_extension("meta")).await;
            // 관련 vary index 는 유지 (다른 variant 가 존재할 수 있음)
            if total >= size {
                total -= size;
            } else {
                total = 0;
            }
        }
    debug!(target: "cache", final_bytes=total, "eviction complete");
        Ok(())
    }

    // base_key 에 대한 Vary 헤더 이름 목록 조회 (없으면 None)
    pub async fn get_vary_header_names(&self, base_key: &str) -> Result<Option<Vec<String>>> {
        let path = self.vary_index_path(base_key);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = match tfs::read(&path).await {
            Ok(b) => b,
            Err(_) => return Ok(None),
        };
        let names: Vec<String> = serde_json::from_slice(&bytes).unwrap_or_default();
        if names.is_empty() {
            return Ok(None);
        }
        Ok(Some(names))
    }

    // base_key 에 대해 Vary 헤더 이름 목록 저장 (이전 값 덮어쓰기)
    pub async fn set_vary_header_names(&self, base_key: &str, names: &[String]) -> Result<()> {
        if names.is_empty() {
            return Ok(());
        }
        let path = self.vary_index_path(base_key);
        if let Some(parent) = path.parent() {
            tfs::create_dir_all(parent).await?;
        }
        let data = serde_json::to_vec(names)?;
        let mut f = tfs::File::create(path).await?;
        f.write_all(&data).await?;
        f.sync_all().await?;
        Ok(())
    }
}
