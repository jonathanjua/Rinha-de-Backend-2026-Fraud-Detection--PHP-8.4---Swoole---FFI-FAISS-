/* faiss.h — Subset da FAISS C API que usamos via PHP FFI.
 *
 * Funções declaradas aqui devem corresponder exatamente às exportadas por
 * libfaiss_c.so. Mantida intencionalmente mínima — só o que build.php e
 * server.php precisam.
 */

typedef long idx_t;

typedef struct FaissIndex_H    FaissIndex;
typedef struct FaissIndexIVF_H FaissIndexIVF;

typedef enum {
    METRIC_INNER_PRODUCT = 0,
    METRIC_L2 = 1,
} FaissMetricType;

/* ── Factory + lifecycle ──────────────────────────────────────────── */
int  faiss_index_factory(FaissIndex** p_index, int d,
                         const char* description, FaissMetricType metric);
void faiss_Index_free(FaissIndex* obj);

/* ── Train + Add (build phase) ────────────────────────────────────── */
int faiss_Index_train(FaissIndex* index, idx_t n, const float* x);
int faiss_Index_add  (FaissIndex* index, idx_t n, const float* x);

/* ── Search (hot path) ────────────────────────────────────────────── */
int faiss_Index_search(const FaissIndex* index, idx_t n, const float* x,
                       idx_t k, float* distances, idx_t* labels);

/* ── I/O ──────────────────────────────────────────────────────────── */
int faiss_write_index_fname(const FaissIndex* idx, const char* fname);
int faiss_read_index_fname (const char* fname, int io_flags,
                            FaissIndex** p_out);

/* ── IVF tuning (downcast helper + nprobe setter) ─────────────────── */
FaissIndexIVF* faiss_IndexIVF_cast(FaissIndex* index);
void faiss_IndexIVF_set_nprobe(FaissIndexIVF* index, size_t nprobe);

/* ── Última mensagem de erro, p/ debug ────────────────────────────── */
const char* faiss_get_last_error();
