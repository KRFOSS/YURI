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

**YU-RI**는 리눅스 미러용 고급 캐시기능이 있는 프록시 서버 입니다.


---

## Build

```bash
cargo build -r
```
