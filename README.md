# Rinha de Backend — Fraud Detection (PHP 8.4 + Swoole + FFI/FAISS)

API de detecção de fraude em transações de cartão para a Rinha de Backend.
A decisão é feita por **kNN com K=5** sobre 3 milhões de transações de
referência: se 3+ dos 5 vizinhos mais próximos são fraudes, a transação é
reprovada.

Score final em testes oficiais: **5311** (de 2062 inicial → +158%).

---

## Stack

| Componente | Papel |
|---|---|
| **PHP 8.4 CLI** | Runtime da API (com JIT tracing) |
| **Swoole** | HTTP server async, single-worker, corrotinas |
| **FFI** | Bridge PHP ↔ libfaiss_c.so (zero-copy de buffers float) |
| **FAISS 1.8** | kNN aproximado (`IVF4096,Flat`, nprobe=8) |
| **nginx 1.27** | Load balancer round-robin (unix socket) |
| **Docker Compose** | Orquestração + cgroup limits |

## Orçamento de recursos (cap rígido da Rinha)

| Container | CPU | Memória |
|---|---|---|
| nginx | 0.10 | 10 MB |
| api1 | 0.45 | 170 MB |
| api2 | 0.45 | 170 MB |
| **Total** | **1.00** | **350 MB** |

---

## Endpoints

```http
GET /ready
→ 200 "ok" quando o índice está carregado
```

```http
POST /fraud-score
Content-Type: application/json

{
  "id": "tx-3576980410",
  "transaction":      { "amount": 384.88, "installments": 3, "requested_at": "2026-03-11T20:23:35Z" },
  "customer":         { "avg_amount": 769.76, "tx_count_24h": 3, "known_merchants": ["MERC-009", "MERC-001"] },
  "merchant":         { "id": "MERC-001", "mcc": "5912", "avg_amount": 298.95 },
  "terminal":         { "is_online": false, "card_present": true, "km_from_home": 13.71 },
  "last_transaction": { "timestamp": "2026-03-11T14:58:35Z", "km_from_current": 18.86 }
}

→ 200
{ "approved": true, "fraud_score": 0.0 }
```

`last_transaction` pode ser `null` (primeira transação do cliente — gera
sentinela `-1` nas dims 5 e 6 do vetor).

---

## Como rodar

### Pré-requisitos

- **Docker + Docker Compose** v2 (testado em v5.x)
- Usuário no grupo `docker` (ou usar `sudo`/`sg docker`)
- Porta **9999** livre
- ~6 GB RAM livres durante o build (json_decode de 3M registros)
- ~5 GB de disco temporário (clonar/compilar FAISS)
- CPU com **AVX2** (Intel Haswell+ ou AMD Excavator+); para outras
  arquiteturas, trocar `-DFAISS_OPT_LEVEL=avx2` por `generic` no
  `Dockerfile.api`

### Subir a stack

```bash
docker compose up --build -d
```

Primeiro build leva **15–20 min** (compila FAISS do zero, instala Swoole
via PECL, processa 3M registros pra construir o índice). Builds seguintes
reusam cache.

### Validar

```bash
curl http://localhost:9999/ready
# → ok

curl -X POST http://localhost:9999/fraud-score \
  -H 'Content-Type: application/json' \
  -d '{"id":"tx-1","transaction":{"amount":41.12,"installments":2,"requested_at":"2026-03-11T18:45:53Z"},"customer":{"avg_amount":82.24,"tx_count_24h":3,"known_merchants":["MERC-016"]},"merchant":{"id":"MERC-016","mcc":"5411","avg_amount":60.25},"terminal":{"is_online":false,"card_present":true,"km_from_home":29.23},"last_transaction":null}'
# → {"approved":true,"fraud_score":0}
```

### Encerrar

```bash
docker compose down -v
```

---

## Estrutura

```
.
├── docker-compose.yml    Orquestração + cgroup limits + volume socket
├── Dockerfile.api        4 stages: faiss-build → php-base → index-build → runtime
├── nginx.conf            Load balancer round-robin via unix socket
├── faiss.h               Subset do C API do FAISS pra FFI::cdef
├── build.php             Pré-processamento offline (image build time)
├── server.php            HTTP server + hot path
└── resources/
    ├── references.json.gz   3M vetores + labels (vem da Rinha)
    └── mcc_risk.json        Tabela MCC → risco
```

## Pipeline de uma request (hot path)

1. `nginx:9999` → unix socket → api{1,2}
2. Swoole recebe → parser regex extrai 14 campos do JSON (fallback `json_decode`)
3. Vetorização inline pras 14 dimensões → buffer FFI float[14]
4. `faiss_Index_search` (FFI) — IVF + Flat, nprobe=8 → 5 vizinhos
5. Lookup das labels via bitmap bit-shift (375 KB, todo em RAM)
6. Score = fraudes/5; resposta JSON via concat de string

p99 medido sob carga: **~1.75 ms**.

---

## Otimizações aplicadas

| # | Otimização | Ganho no final_score |
|---|---|---|
| 1 | Unix socket nginx ↔ api (em vez de TCP loopback) | base |
| 2 | Pre-warm: drena índice no page cache + 8 dummy searches | base |
| 3 | mmap do índice FAISS (compartilhado entre api1/api2 via page cache) | base |
| 4 | Índice `IVF4096,Flat` (busca exata dentro das 8 cells mais próximas) | +1235 |
| 5 | `nprobe=8` (em vez de 16) — sweet spot accuracy × latência | +109 |
| 6 | Memory rebalance 30/160/160 → 10/170/170 (menos page eviction) | +103 |
| 7 | Parser regex pra payload no schema canônico (1 PCRE vs json_decode) | marginal |
| 8 | `days_from_civil` (Howard Hinnant) inline em vez de `gmmktime` | marginal |
| 9 | OpCache com JIT tracing | mantém |
| 10 | Bitmap de labels (1 bit por referência) — 375 KB cabem em L2 | base |

### Tentativas que regrediram (não estão no código final)

- `OPQ14_56,IVF4096,SQ8` — OPQ é otimizado pra PQ, atrapalha SQ
- Whitening (z-score por dim) — distorce features binárias (is_online etc.)
- `nprobe=24` — mais accuracy não compensa o p99 maior
- Desabilitar JIT — sob carga, p99 sobe ~73%

---

## Decisões de modelagem

- **Vetorização das 14 dims** segue exatamente `REGRAS_DE_DETECCAO.md`:
  features contínuas com clamp em `[0,1]`, binárias 0/1, sentinela `-1`
  pra `last_transaction = null`.
- **`mcc_risk.json`** mapeia MCC → risco em `[0,1]`. MCCs ausentes caem no
  default `0.5` (conforme spec).
- **Índice FAISS reproduzível**: rebuild reproduz índice idêntico (treino
  IVF é determinístico com seed fixo do FAISS).
- **`memory_limit=4G` no `build.php`**: `json_decode` de 3M registros
  consome ~1–2 GB de arrays PHP. Sob runtime, cada API usa apenas 140 MB
  (`memory_limit` configurado no `php.ini`).
