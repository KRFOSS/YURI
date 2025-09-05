# YU-RI (유리)

```txt
                   YU-RI                      
                    ___                       
1.  Request───────>|\  \                      
                   | \ _\                     
                   |  |  |<───────>3. Upstream
2.    Cache<───────|  |  |                    
                    \ |  |                    
4. Response<─────────\|__|                    
```

```txt
1. Request to YU-RI
2. Cache Check ----> HIT = 4. Response
                └--> MISS or TTL Expired = 3. Upstream ---> 4. Response
```

**YU-RI**는 리눅스 미러용 고급 캐시기능이 있는 고성능 프록시 서버 입니다.

---

## Use

- docker

```yaml
name: yu-ri
services:
  yu-ri:
    container_name: yu-ri
    environment:
      - CACHE_DIR=/var/cache/yu-ri
      - DEFAULT_TTL_SECS=300
      - EVICTION_POLICY=LRU
      - LISTEN_ADDR=0.0.0.0:7878
      - MAX_CACHE_SIZE_BYTES=107374182400
      - RUST_LOG=debug
      - UPSTREAM_BASE=https://mirror.techlabs.co.kr
    hostname: yu-ri
    image: ghcr.io/krfoss/yu-ri:latest
    ports:
      - target: 7878
        published: "7878"
        protocol: tcp
    restart: unless-stopped
    volumes:
      - type: bind
        source: /var/cache/yu-ri
        target: /var/cache/yu-ri
    network_mode: bridge
    privileged: false
```

## Build

```bash
cargo build -r
```
