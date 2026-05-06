<?php
/**
 * server.php — API HTTP de detecção de fraude (hot path).
 *
 * Endpoints:
 *   GET  /ready         → 200 "ok" quando o índice está carregado
 *   POST /fraud-score   → vetoriza payload nested, kNN no FAISS, score
 *
 * Otimizações de runtime:
 *   • Unix socket nginx ↔ api (sem overhead de TCP loopback)
 *   • Pre-warm: drena o arquivo do índice no page cache + 8 dummy searches
 *     pra aquecer OpenMP threads, buffers internos e o JIT do PHP.
 *   • Parser regex pra payload no schema canônico (1 chamada PCRE em vez de
 *     json_decode + array nested PHP); fallback pra json_decode se não bater.
 *   • days_from_civil (Howard Hinnant) inline pra delta de minutos sem
 *     chamar gmmktime (pura aritmética, ~10× mais rápido).
 */

declare(strict_types=1);

// ─── Constantes ──────────────────────────────────────────────────
const DIMS              = 14;
const K                 = 5;
const FRAUD_THRESHOLD   = 0.6;

// FAISS_IO_FLAG_MMAP — carrega índice em modo mmap (compartilhável)
const FAISS_IO_FLAG_MMAP = 0x646F0000 | 0x1;

// /resources/normalization.json (embutido — valores fixos da spec)
const MAX_AMOUNT              = 10000.0;
const MAX_INSTALLMENTS        = 12.0;
const AMOUNT_VS_AVG_RATIO     = 10.0;
const MAX_MINUTES             = 1440.0;
const MAX_KM                  = 1000.0;
const MAX_TX_COUNT_24H        = 20.0;
const MAX_MERCHANT_AVG_AMOUNT = 10000.0;
const MCC_DEFAULT             = 0.5;

// Regex canônico do payload — ordem do exemplo da spec (transaction → customer
// → merchant → terminal → last_transaction). Captura 15 grupos:
//   1: amount, 2: installments, 3: requested_at,
//   4: cust_avg_amount, 5: tx_count_24h, 6: known_merchants_raw,
//   7: merch_id, 8: mcc, 9: merch_avg,
//   10: is_online, 11: card_present, 12: km_from_home,
//   13: last_transaction (null ou {...}), 14: last_ts, 15: last_km
const PAYLOAD_REGEX = '~"transaction":\s*\{[^}]*?"amount":\s*([\d.eE+\-]+)[^}]*?"installments":\s*(\d+)[^}]*?"requested_at":\s*"([^"]+)"[^}]*?\}[^{]*?"customer":\s*\{[^}]*?"avg_amount":\s*([\d.eE+\-]+)[^}]*?"tx_count_24h":\s*(\d+)[^}]*?"known_merchants":\s*\[([^\]]*)\][^}]*?\}[^{]*?"merchant":\s*\{[^}]*?"id":\s*"([^"]+)"[^}]*?"mcc":\s*"([^"]+)"[^}]*?"avg_amount":\s*([\d.eE+\-]+)[^}]*?\}[^{]*?"terminal":\s*\{[^}]*?"is_online":\s*(true|false)[^}]*?"card_present":\s*(true|false)[^}]*?"km_from_home":\s*([\d.eE+\-]+)[^}]*?\}[^{]*?"last_transaction":\s*(null|\{[^}]*?"timestamp":\s*"([^"]+)"[^}]*?"km_from_current":\s*([\d.eE+\-]+)[^}]*?\})~';

// ─── Configuração via env ────────────────────────────────────────
$indexPath  = getenv('INDEX_PATH')    ?: '/data/index.faiss';
$labelsPath = getenv('LABELS_PATH')   ?: '/data/labels.bin';
$mccPath    = getenv('MCC_RISK_PATH') ?: '/data/mcc_risk.json';
$socketPath = getenv('SOCKET_PATH')   ?: '';
$port       = (int)(getenv('SERVER_PORT') ?: 9501);

// ─── FFI: carrega FAISS ──────────────────────────────────────────
$faiss = FFI::cdef(file_get_contents(__DIR__ . '/faiss.h'), 'libfaiss_c.so');

// ─── Pre-warm: drena o arquivo do índice no page cache ──────────
$fp = fopen($indexPath, 'rb');
if ($fp) {
    while (!feof($fp)) fread($fp, 65536);
    fclose($fp);
}

// ─── Abre o índice via mmap ──────────────────────────────────────
$indexHolder = $faiss->new('FaissIndex*[1]');
$rc = $faiss->faiss_read_index_fname($indexPath, FAISS_IO_FLAG_MMAP, $indexHolder);
if ($rc !== 0) {
    $err = FFI::string($faiss->faiss_get_last_error() ?? '(null)');
    fwrite(STDERR, "faiss_read_index_fname failed (rc=$rc): $err\n");
    exit(1);
}
$index = $indexHolder[0];

// ─── Bitmap de fraude ────────────────────────────────────────────
$labels = file_get_contents($labelsPath);
if ($labels === false) {
    fwrite(STDERR, "Failed to read $labelsPath\n");
    exit(1);
}

// ─── MCC risk table (string → float) ─────────────────────────────
$mccRisk = is_file($mccPath)
    ? (json_decode((string)file_get_contents($mccPath), true) ?: [])
    : [];

// ─── Buffers FFI pré-alocados ────────────────────────────────────
$queryBuf = $faiss->new('float[' . DIMS . ']');
$distBuf  = $faiss->new('float[' . K    . ']');
$idBuf    = $faiss->new('int64_t[' . K  . ']');

// ─── Pre-warm searches ───────────────────────────────────────────
$warmup = $faiss->new('float[' . DIMS . ']');
for ($d = 0; $d < DIMS; $d++) $warmup[$d] = 0.5;
for ($k = 0; $k < 8; $k++) {
    $faiss->faiss_Index_search($index, 1, $warmup, K, $distBuf, $idBuf);
}
unset($warmup);

fprintf(
    STDERR,
    "[server] index loaded, %d label bytes, %d MCC entries\n",
    strlen($labels), count($mccRisk)
);

// ─── Day-of-week (Mon=0..Sun=6) via Zeller ───────────────────────
function dow_mon0(int $y, int $m, int $d): int {
    if ($m < 3) { $m += 12; $y--; }
    $K = $y % 100;
    $J = intdiv($y, 100);
    $h = ($d + intdiv(13 * ($m + 1), 5) + $K + intdiv($K, 4) + intdiv($J, 4) + 5 * $J) % 7;
    return ($h + 5) % 7;
}

// ─── days_from_civil (Howard Hinnant) ────────────────────────────
//   Retorna o nº de dias desde 1970-01-01 (epoch) sem tabelas, sem syscall,
//   sem dependência de timezone do sistema. ~10 ops aritméticas inteiras.
function days_from_civil(int $y, int $m, int $d): int {
    $y -= ($m <= 2) ? 1 : 0;
    $era = intdiv($y >= 0 ? $y : $y - 399, 400);
    $yoe = $y - $era * 400;
    $doy = intdiv(153 * ($m > 2 ? $m - 3 : $m + 9) + 2, 5) + $d - 1;
    $doe = $yoe * 365 + intdiv($yoe, 4) - intdiv($yoe, 100) + $doy;
    return $era * 146097 + $doe - 719468;
}

// ─── Swoole HTTP Server (unix socket ou TCP) ─────────────────────
if ($socketPath !== '') {
    @unlink($socketPath);
    $server = new Swoole\Http\Server($socketPath, 0, SWOOLE_BASE, SWOOLE_UNIX_STREAM);
} else {
    $server = new Swoole\Http\Server('0.0.0.0', $port, SWOOLE_BASE);
}

$server->set([
    'worker_num'         => 1,
    'enable_coroutine'   => true,
    'http_compression'   => false,
    'log_level'          => SWOOLE_LOG_WARNING,
    'open_tcp_keepalive' => true,
    'tcp_keepidle'       => 60,
    'buffer_output_size' => 4 * 1024,
    'socket_buffer_size' => 128 * 1024,
    'max_coroutine'      => 10_000,
]);

$server->on('start', static function () use ($socketPath, $port): void {
    if ($socketPath !== '') {
        @chmod($socketPath, 0666);
        fprintf(STDERR, "[server] ready on %s\n", $socketPath);
    } else {
        fprintf(STDERR, "[server] ready on :%d\n", $port);
    }
});

$server->on('request', static function (
    Swoole\Http\Request $req,
    Swoole\Http\Response $res
) use ($faiss, $index, $labels, $mccRisk, $queryBuf, $distBuf, $idBuf): void {

    $uri = $req->server['request_uri'] ?? '/';

    // ── GET /ready ───────────────────────────────────────────────
    if ($uri === '/ready') {
        $res->end('ok');
        return;
    }

    // ── POST /fraud-score ────────────────────────────────────────
    if ($uri !== '/fraud-score') {
        $res->status(404);
        $res->end('{"error":"not_found"}');
        return;
    }

    $body = $req->rawContent();
    if (!$body) {
        $res->status(400);
        $res->end('{"error":"empty_body"}');
        return;
    }

    // ── Parsing ──────────────────────────────────────────────────
    //   Tenta regex (schema canônico). Se falhar, cai em json_decode.
    if (preg_match(PAYLOAD_REGEX, $body, $m)) {
        $amount         = (float)$m[1];
        $installments   = (float)$m[2];
        $requestedAt    = $m[3];
        $custAvg        = (float)$m[4];
        $txCount24h     = (float)$m[5];
        $knownStr       = $m[6];   // raw string do array known_merchants
        $merchId        = $m[7];
        $mcc            = $m[8];
        $merchAvg       = (float)$m[9];
        $isOnline       = $m[10] === 'true';
        $cardPresent    = $m[11] === 'true';
        $kmFromHome     = (float)$m[12];
        $lastIsNull     = $m[13] === 'null';
        $lastTs         = $lastIsNull ? null : $m[14];
        $lastKm         = $lastIsNull ? 0.0 : (float)$m[15];
        // unknown_merchant: testa string-search em vez de in_array
        $merchInKnown   = $knownStr !== '' && strpos($knownStr, '"' . $merchId . '"') !== false;
    } else {
        $p = json_decode($body, true);
        if (!is_array($p)) {
            $res->status(400);
            $res->end('{"error":"invalid_json"}');
            return;
        }
        $tx    = $p['transaction']      ?? [];
        $cust  = $p['customer']         ?? [];
        $merch = $p['merchant']         ?? [];
        $term  = $p['terminal']         ?? [];
        $last  = $p['last_transaction'] ?? null;

        $amount       = (float)($tx['amount']           ?? 0);
        $installments = (float)($tx['installments']     ?? 0);
        $requestedAt  = (string)($tx['requested_at']    ?? '1970-01-01T00:00:00Z');
        $custAvg      = (float)($cust['avg_amount']     ?? 0);
        $txCount24h   = (float)($cust['tx_count_24h']   ?? 0);
        $merchId      = (string)($merch['id']           ?? '');
        $mcc          = (string)($merch['mcc']          ?? '');
        $merchAvg     = (float)($merch['avg_amount']    ?? 0);
        $isOnline     = !empty($term['is_online']);
        $cardPresent  = !empty($term['card_present']);
        $kmFromHome   = (float)($term['km_from_home']   ?? 0);
        $known        = $cust['known_merchants']        ?? [];
        $merchInKnown = is_array($known) && in_array($merchId, $known, true);

        if (is_array($last)) {
            $lastIsNull = false;
            $lastTs     = (string)($last['timestamp']       ?? '1970-01-01T00:00:00Z');
            $lastKm     = (float)($last['km_from_current'] ?? 0);
        } else {
            $lastIsNull = true;
            $lastTs     = null;
            $lastKm     = 0.0;
        }
    }

    // ── Vetorização (14 dims, REGRAS_DE_DETECCAO.md) ─────────────

    // 0. amount
    $queryBuf[0] = $amount >= MAX_AMOUNT ? 1.0 : ($amount <= 0 ? 0.0 : $amount / MAX_AMOUNT);

    // 1. installments
    $queryBuf[1] = $installments >= MAX_INSTALLMENTS ? 1.0 : ($installments <= 0 ? 0.0 : $installments / MAX_INSTALLMENTS);

    // 2. amount_vs_avg
    if ($custAvg > 0) {
        $r = ($amount / $custAvg) / AMOUNT_VS_AVG_RATIO;
        $queryBuf[2] = $r >= 1.0 ? 1.0 : ($r <= 0 ? 0.0 : $r);
    } else {
        $queryBuf[2] = 1.0;
    }

    // 3-4. hour_of_day + day_of_week — parse manual do ISO 8601 fixo
    $year  = (int)substr($requestedAt, 0, 4);
    $month = (int)substr($requestedAt, 5, 2);
    $day   = (int)substr($requestedAt, 8, 2);
    $hour  = (int)substr($requestedAt, 11, 2);
    $cMi   = (int)substr($requestedAt, 14, 2);
    $cS    = (int)substr($requestedAt, 17, 2);
    $queryBuf[3] = $hour / 23.0;
    $queryBuf[4] = dow_mon0($year, $month, $day) / 6.0;

    // 5-6. last_transaction (null → -1.0 sentinela)
    if ($lastIsNull) {
        $queryBuf[5] = -1.0;
        $queryBuf[6] = -1.0;
    } else {
        // 5. minutes_since_last — diff via days_from_civil + seconds-of-day,
        //    pura aritmética inteira, sem syscall.
        if (is_string($lastTs) && strlen($lastTs) >= 19) {
            $lY  = (int)substr($lastTs, 0, 4);
            $lMo = (int)substr($lastTs, 5, 2);
            $lD  = (int)substr($lastTs, 8, 2);
            $lH  = (int)substr($lastTs, 11, 2);
            $lMi = (int)substr($lastTs, 14, 2);
            $lS  = (int)substr($lastTs, 17, 2);

            if ($year === $lY && $month === $lMo && $day === $lD) {
                // Mesmo dia — atalho sem dias-from-epoch
                $diffSec = ($hour - $lH) * 3600 + ($cMi - $lMi) * 60 + ($cS - $lS);
            } else {
                $diffSec = (days_from_civil($year, $month, $day) - days_from_civil($lY, $lMo, $lD)) * 86400
                         + ($hour * 3600 + $cMi * 60 + $cS) - ($lH * 3600 + $lMi * 60 + $lS);
            }
            $minutes = $diffSec < 0 ? 0 : $diffSec / 60.0;
            $queryBuf[5] = $minutes >= MAX_MINUTES ? 1.0 : $minutes / MAX_MINUTES;
        } else {
            $queryBuf[5] = -1.0;
        }
        // 6. km_from_last_tx
        $queryBuf[6] = $lastKm >= MAX_KM ? 1.0 : ($lastKm <= 0 ? 0.0 : $lastKm / MAX_KM);
    }

    // 7. km_from_home
    $queryBuf[7] = $kmFromHome >= MAX_KM ? 1.0 : ($kmFromHome <= 0 ? 0.0 : $kmFromHome / MAX_KM);

    // 8. tx_count_24h
    $queryBuf[8] = $txCount24h >= MAX_TX_COUNT_24H ? 1.0 : ($txCount24h <= 0 ? 0.0 : $txCount24h / MAX_TX_COUNT_24H);

    // 9-10. is_online / card_present
    $queryBuf[9]  = $isOnline    ? 1.0 : 0.0;
    $queryBuf[10] = $cardPresent ? 1.0 : 0.0;

    // 11. unknown_merchant (1 = desconhecido)
    $queryBuf[11] = $merchInKnown ? 0.0 : 1.0;

    // 12. mcc_risk
    $queryBuf[12] = (float)($mccRisk[$mcc] ?? MCC_DEFAULT);

    // 13. merchant_avg_amount
    $queryBuf[13] = $merchAvg >= MAX_MERCHANT_AVG_AMOUNT ? 1.0 : ($merchAvg <= 0 ? 0.0 : $merchAvg / MAX_MERCHANT_AVG_AMOUNT);

    // ── kNN: 5 vizinhos mais próximos ────────────────────────────
    $faiss->faiss_Index_search($index, 1, $queryBuf, K, $distBuf, $idBuf);

    // ── Conta fraudes via bitmap lookup ──────────────────────────
    $frauds = 0;
    for ($i = 0; $i < K; $i++) {
        $id = $idBuf[$i];
        if ($id < 0) continue;
        $byte = $id >> 3;
        $bit  = $id & 7;
        $frauds += (ord($labels[$byte]) >> $bit) & 1;
    }

    $score    = $frauds / K;
    $approved = $score < FRAUD_THRESHOLD;

    $res->header('Content-Type', 'application/json');
    $res->end(
        '{"approved":' . ($approved ? 'true' : 'false')
        . ',"fraud_score":' . $score . '}'
    );
});

$server->on('shutdown', static function () use ($faiss, $index): void {
    $faiss->faiss_Index_free($index);
});

$server->start();
