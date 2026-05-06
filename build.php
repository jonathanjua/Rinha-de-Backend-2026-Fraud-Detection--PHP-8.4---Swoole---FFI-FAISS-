<?php
/**
 * build.php — Pré-processamento offline (image build time).
 *
 * Lê /build/references.json.gz no formato:
 *   [{"vector":[14 floats], "label":"legit"|"fraud"}, ...]
 *
 * Os vetores já vêm normalizados pela organização da Rinha — o build aqui
 * só copia floats para um buffer FFI contíguo, marca o label como bit num
 * bitmap, e treina/grava um índice FAISS IVF4096,Flat para mmap em runtime.
 *
 * Saídas:
 *   /build/index.faiss   índice quantizado (~25–45 MB)
 *   /build/labels.bin    bitmap: 1 bit por referência (1=fraud)
 */

declare(strict_types=1);

const INPUT      = '/build/references.json.gz';
const OUT_INDEX  = '/build/index.faiss';
const OUT_LABELS = '/build/labels.bin';
const DIMS       = 14;
const TRAIN_SIZE = 200_000;
const NPROBE     = 8;
const METRIC_L2  = 1;

$faiss = FFI::cdef(file_get_contents(__DIR__ . '/faiss.h'), 'libfaiss_c.so');

function check(int $rc, string $what): void {
    if ($rc !== 0) {
        global $faiss;
        $err = FFI::string($faiss->faiss_get_last_error() ?? '(null)');
        fwrite(STDERR, "[FAISS] $what failed (rc=$rc): $err\n");
        exit(1);
    }
}

// ─── 1. Lê e descomprime ─────────────────────────────────────────
fwrite(STDERR, "[1/4] Reading " . INPUT . "...\n");
$raw = gzdecode(file_get_contents(INPUT));
if ($raw === false) { fwrite(STDERR, "gzdecode failed\n"); exit(1); }
$records = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
unset($raw);

$n = count($records);
fwrite(STDERR, "      Loaded $n records\n");

// ─── 2. Copia vetores → buffer FFI; labels → bitmap ──────────────
fwrite(STDERR, "[2/4] Filling FFI buffers (" . intval($n * DIMS * 4 / 1048576) . " MB)...\n");
$vectors      = $faiss->new('float[' . ($n * DIMS) . ']');
$labelsBitmap = str_repeat("\x00", intdiv($n + 7, 8));

$base = 0;
foreach ($records as $i => $r) {
    $v = $r['vector'];
    // Loop unrolled — 14 dims fixas
    $vectors[$base + 0]  = (float)$v[0];
    $vectors[$base + 1]  = (float)$v[1];
    $vectors[$base + 2]  = (float)$v[2];
    $vectors[$base + 3]  = (float)$v[3];
    $vectors[$base + 4]  = (float)$v[4];
    $vectors[$base + 5]  = (float)$v[5];
    $vectors[$base + 6]  = (float)$v[6];
    $vectors[$base + 7]  = (float)$v[7];
    $vectors[$base + 8]  = (float)$v[8];
    $vectors[$base + 9]  = (float)$v[9];
    $vectors[$base + 10] = (float)$v[10];
    $vectors[$base + 11] = (float)$v[11];
    $vectors[$base + 12] = (float)$v[12];
    $vectors[$base + 13] = (float)$v[13];
    $base += DIMS;

    if ($r['label'] === 'fraud') {
        $byte = $i >> 3;
        $bit  = $i & 7;
        $labelsBitmap[$byte] = chr(ord($labelsBitmap[$byte]) | (1 << $bit));
    }

    if (($i & 0xFFFFF) === 0 && $i > 0) {
        fwrite(STDERR, sprintf("      %s / %s\n", number_format($i), number_format($n)));
    }
}
unset($records);  // libera os arrays PHP

file_put_contents(OUT_LABELS, $labelsBitmap);
unset($labelsBitmap);
fwrite(STDERR, "      Wrote " . OUT_LABELS . "\n");

// ─── 3. Treina + popula o índice IVF4096,Flat ─────────────────────
fwrite(STDERR, "[3/4] Building IVF4096,Flat index...\n");

$indexHolder = $faiss->new('FaissIndex*[1]');
check($faiss->faiss_index_factory($indexHolder, DIMS, "IVF4096,Flat", METRIC_L2), 'index_factory');
$index = $indexHolder[0];

$trainN = min(TRAIN_SIZE, $n);
fwrite(STDERR, "      Training on $trainN samples...\n");

$trainBuf = $faiss->new('float[' . ($trainN * DIMS) . ']');
$step = intdiv($n, $trainN);
$dst = 0;
for ($i = 0; $i < $trainN; $i++) {
    $src = ($i * $step) * DIMS;
    for ($d = 0; $d < DIMS; $d++) {
        $trainBuf[$dst++] = $vectors[$src + $d];
    }
}
check($faiss->faiss_Index_train($index, $trainN, $trainBuf), 'train');
unset($trainBuf);

fwrite(STDERR, "      Adding $n vectors...\n");
check($faiss->faiss_Index_add($index, $n, $vectors), 'add');

$ivf = $faiss->faiss_IndexIVF_cast($index);
if ($ivf !== null) {
    $faiss->faiss_IndexIVF_set_nprobe($ivf, NPROBE);
    fwrite(STDERR, "      nprobe = " . NPROBE . "\n");
}

// ─── 4. Persiste ─────────────────────────────────────────────────
fwrite(STDERR, "[4/4] Writing " . OUT_INDEX . "...\n");
check($faiss->faiss_write_index_fname($index, OUT_INDEX), 'write_index');
$faiss->faiss_Index_free($index);
unset($vectors);

fwrite(STDERR, sprintf("      Done. index.faiss = %.2f MB\n", filesize(OUT_INDEX) / 1048576));
