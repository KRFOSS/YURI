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
                └--> MISS = 3. Upstream ---> 4. Response
```

---

## Build

```bash
cargo build -r
```
