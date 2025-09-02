use http::HeaderMap;
use std::time::{Duration, SystemTime};

/// 결과 TTL 및 캐시 여부 판단용
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TtlDecision {
    pub ttl: Option<Duration>, // None 이면 저장시 default TTL 사용
    pub cacheable: bool,
    pub stale_while_revalidate: Option<Duration>, // stale-while-revalidate=N 지원
}

impl TtlDecision {
    pub fn not_cacheable() -> Self {
        Self {
            ttl: None,
            cacheable: false,
            stale_while_revalidate: None,
        }
    }
    pub fn with_ttl(d: Duration) -> Self {
        Self {
            ttl: Some(d),
            cacheable: true,
            stale_while_revalidate: None,
        }
    }
    pub fn default_cacheable() -> Self {
        Self {
            ttl: None,
            cacheable: true,
            stale_while_revalidate: None,
        }
    }
}

/// Cache-Control / Expires 헤더를 파싱해 TTL 을 결정.
/// 규칙(간단화):
/// 1. Cache-Control 존재시 우선.
///    - no-store | private | no-cache => 비캐시
///    - max-age=N => N초 (0 이면 비캐시)
///    - s-maxage=N => 공유 프록시용, 있으면 우선적으로 사용
/// 2. Expires (HTTP-date) 가 있고 현재보다 미래면 그 차이(초) 사용. (Cache-Control max-age/s-maxage 보다 후순위)
/// 3. 아무것도 없으면 기본 TTL 사용 (None 반환 + cacheable=true)
pub fn derive_ttl(headers: &HeaderMap, now: SystemTime) -> TtlDecision {
    use http::header;
    if let Some(cc_val) = headers
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
    {
        let mut max_age: Option<i64> = None;
        let mut s_maxage: Option<i64> = None;
        let mut swr: Option<i64> = None;
        for part in cc_val.split(',') {
            let token = part.trim().to_ascii_lowercase();
            if token == "no-store" || token == "no-cache" || token == "private" {
                // private 은 공유 캐시 입장에서 비캐시 처리
                return TtlDecision::not_cacheable();
            }
            if let Some(rest) = token.strip_prefix("s-maxage=") {
                if let Ok(v) = rest.parse::<i64>() {
                    s_maxage = Some(v.max(0));
                }
            } else if let Some(rest) = token.strip_prefix("max-age=") {
                if let Ok(v) = rest.parse::<i64>() {
                    max_age = Some(v.max(0));
                }
            } else if let Some(rest) = token.strip_prefix("stale-while-revalidate=") {
                if let Ok(v) = rest.parse::<i64>() {
                    swr = Some(v.max(0));
                }
            }
        }
        let chosen = s_maxage.or(max_age);
        if let Some(sec) = chosen {
            if sec == 0 {
                return TtlDecision::not_cacheable();
            }
            let mut d = TtlDecision::with_ttl(Duration::from_secs(sec as u64));
            if let Some(s) = swr {
                if s > 0 {
                    d.stale_while_revalidate = Some(Duration::from_secs(s as u64));
                }
            }
            return d;
        }
    }
    // Expires 처리 (Cache-Control max-age 없을 때만)
    if let Some(exp_val) = headers.get("Expires").and_then(|v| v.to_str().ok()) {
        if let Ok(exp_time) = httpdate::parse_http_date(exp_val) {
            // httpdate crate
            if let Ok(diff) = exp_time.duration_since(now) {
                // 0 초면 비캐시로 간주 (혹은 default? 여기선 비캐시)
                if diff.as_secs() == 0 {
                    return TtlDecision::not_cacheable();
                }
                return TtlDecision::with_ttl(diff);
            } else {
                // 이미 지난날 => 비캐시
                return TtlDecision::not_cacheable();
            }
        }
    }
    // 기본
    TtlDecision::default_cacheable()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;
    use std::time::{Duration, SystemTime};

    #[test]
    fn test_max_age() {
        let mut h = HeaderMap::new();
        h.insert("Cache-Control", "max-age=120".parse().unwrap());
        let d = derive_ttl(&h, SystemTime::now());
        assert_eq!(d.ttl, Some(Duration::from_secs(120)));
        assert!(d.cacheable);
    }

    #[test]
    fn test_s_maxage_precedence() {
        let mut h = HeaderMap::new();
        h.insert("Cache-Control", "max-age=10, s-maxage=20".parse().unwrap());
        let d = derive_ttl(&h, SystemTime::now());
        assert_eq!(d.ttl, Some(Duration::from_secs(20)));
    }

    #[test]
    fn test_no_store() {
        let mut h = HeaderMap::new();
        h.insert("Cache-Control", "no-store".parse().unwrap());
        let d = derive_ttl(&h, SystemTime::now());
        assert!(!d.cacheable);
    }

    #[test]
    fn test_expires() {
        let mut h = HeaderMap::new();
        let now = SystemTime::now();
        let future = httpdate::fmt_http_date(now + Duration::from_secs(30));
        h.insert("Expires", future.parse().unwrap());
        let d = derive_ttl(&h, now);
        let secs = d.ttl.unwrap().as_secs();
        assert!(
            secs == 30 || secs == 29,
            "expected ~30 secs ttl, got {}",
            secs
        );
    }

    #[test]
    fn test_expired_expires() {
        let mut h = HeaderMap::new();
        let now = SystemTime::now();
        let past = httpdate::fmt_http_date(now - Duration::from_secs(5));
        h.insert("Expires", past.parse().unwrap());
        let d = derive_ttl(&h, now);
        assert!(!d.cacheable);
    }
}
