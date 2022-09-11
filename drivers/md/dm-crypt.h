#define PD_READ_DURING_HIDDEN_WRITE        0x01
#define PD_HIDDEN_OPERATION         0x02
#define PD_READ_DURING_PUBLIC_WRITE 0x04
#define PD_MAP_MAGIC_DATA  0xBB
/*
 * context holding the current state of a multi-part conversion
 */
struct convert_context {
        struct completion restart;
        struct bio *bio_in;
        struct bio *bio_out;
        struct bvec_iter iter_in;
        struct bvec_iter iter_out;
        u64 cc_sector;
        unsigned int *tag_offset;
        atomic_t cc_pending;
        union {
                struct skcipher_request *req;
                struct aead_request *req_aead;
        } r;

};
struct io_bio_vec {
        struct bio_vec bv;
        struct io_bio_vec *next;
};

/*
 * per bio private data
 */
struct dm_crypt_io {
        struct crypt_config *cc;
        struct bio *base_bio;
        struct bio *write_bio;
        struct bio *write_ctx_bio;
        struct freelist_results **freelist;
	struct completion map_complete;
        u8 *integrity_metadata;
        bool integrity_metadata_from_pool;
        struct work_struct work;
        struct tasklet_struct tasklet;

        struct convert_context ctx;

        atomic_t io_pending;
        blk_status_t error;
        sector_t sector;
        sector_t write_sector;
        sector_t read_sector;

        struct rb_node rb_node;
        unsigned long flags;
        struct io_bio_vec *pages_head;
        struct io_bio_vec *pages_tail;
} CRYPTO_MINALIGN_ATTR;

struct iv_benbi_private {
        int shift;
};

#define LMK_SEED_SIZE 64 /* hash + 0 */
struct iv_lmk_private {
        struct crypto_shash *hash_tfm;
        u8 *seed;
};

#define TCW_WHITENING_SIZE 16
struct iv_tcw_private {
        struct crypto_shash *crc32_tfm;
        u8 *iv_seed;
        u8 *whitening;
};

#define ELEPHANT_MAX_KEY_SIZE 32
struct iv_elephant_private {
        struct crypto_skcipher *tfm;
};


/*
 * The fields in here must be read only after initialization.
 */
struct crypt_config {
        struct dm_dev *dev;
        sector_t start;

        struct percpu_counter n_allocated_pages;

        struct workqueue_struct *io_queue;
        struct workqueue_struct *map_queue;
        struct workqueue_struct *crypt_queue;

        spinlock_t write_thread_lock;
        struct task_struct *write_thread;
        struct task_struct *map_write_thread;
        struct rb_root write_tree;

        char *cipher_string;
        char *cipher_auth;
        char *key_string;

        const struct crypt_iv_operations *iv_gen_ops;
        union {
                struct iv_benbi_private benbi;
                struct iv_lmk_private lmk;
                struct iv_tcw_private tcw;
                struct iv_elephant_private elephant;
        } iv_gen_private;
        u64 iv_offset;
        unsigned int iv_size;
        unsigned short int sector_size;
        unsigned char sector_shift;

        union {
                struct crypto_skcipher **tfms;
                struct crypto_aead **tfms_aead;
        } cipher_tfm;
        unsigned tfms_count;
        unsigned long cipher_flags;

        /*
         * Layout of each crypto request:
         *
         *   struct skcipher_request
         *      context
         *      padding
         *   struct dm_crypt_request
         *      padding
         *   IV
         *
         * The padding is added so that dm_crypt_request and the IV are
         * correctly aligned.
         */
        unsigned int dmreq_start;

        unsigned int per_bio_data_size;

        unsigned long flags;
        unsigned int key_size;
        unsigned int key_parts;      /* independent parts in key buffer */
        unsigned int key_extra_size; /* additional keys length */
        unsigned int key_mac_size;   /* MAC key size for authenc(...) */

        unsigned int integrity_tag_size;
        unsigned int integrity_iv_size;
        unsigned int on_disk_tag_size;

        /*
         * pool for per bio private data, crypto requests,
         * encryption requeusts/buffer pages and integrity tags
         */
        unsigned tag_pool_max_sectors;
        mempool_t tag_pool;
        mempool_t req_pool;
        mempool_t page_pool;

        struct bio_set bs;
        struct mutex bio_alloc_lock;

        u8 *authenc_key; /* space for keys in authenc() format (if used) */
        u8 key[];
};

struct freelist_results {
        unsigned start;
        int len;
};

struct bio *crypt_alloc_buffer(struct dm_crypt_io *io, unsigned size, int integ_offset);
void crypt_convert_init(struct crypt_config *cc,
                               struct convert_context *ctx,
                               struct bio *bio_out, struct bio *bio_in,
                               sector_t sector, unsigned int *tag_offset);
blk_status_t crypt_convert(struct crypt_config *cc,
                        struct convert_context *ctx, bool atomic, bool reset_pending);
void crypt_free_buffer_pages(struct crypt_config *cc, struct bio *clone);

void crypt_inc_pending(struct dm_crypt_io *io);

void crypt_dec_pending(struct dm_crypt_io *io);

int dm_crypt_integrity_io_alloc(struct dm_crypt_io *io, struct bio *bio, int offset);

int getfrom_freelist(int sector_count, struct freelist_results *results);

void map_insert(struct dm_crypt_io *io, unsigned sector, struct freelist_results *res);
