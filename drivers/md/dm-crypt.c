/*
 * Copyright (C) 2003 Jana Saout <jana@saout.de>
 * Copyright (C) 2004 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2006-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2013-2020 Milan Broz <gmazyland@gmail.com>
 *
 * This file is released under the GPL.
 */

#include <linux/completion.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/key.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-integrity.h>
#include <linux/mempool.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/backing-dev.h>
#include <linux/atomic.h>
#include <linux/scatterlist.h>
#include <linux/rbtree.h>
#include <linux/ctype.h>
#include <asm/page.h>
#include <asm/unaligned.h>
#include <crypto/hash.h>
#include <crypto/md5.h>
#include <crypto/algapi.h>
#include <crypto/skcipher.h>
#include <crypto/aead.h>
#include <crypto/authenc.h>
#include <linux/rtnetlink.h> /* for struct rtattr and RTA macros only */
#include <linux/key-type.h>
#include <keys/user-type.h>
#include <keys/encrypted-type.h>
#include <keys/trusted-type.h>

#include <linux/device-mapper.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/idr.h>
#include <linux/module.h>
#include <crypto/hash.h>

#include "dm-audit.h"
#include "dm-crypt.h"

#define DM_MSG_PREFIX "crypt"

static DEFINE_IDR(map_idr);

static DEFINE_SPINLOCK(map_lock);
static DEFINE_SPINLOCK(freelist_lock);

struct dm_crypt_request {
	struct convert_context *ctx;
	struct scatterlist sg_in[4];
	struct scatterlist sg_out[4];
	u64 iv_sector;
};

struct crypt_config;

struct crypt_iv_operations {
	int (*ctr)(struct crypt_config *cc, struct dm_target *ti,
			const char *opts);
	void (*dtr)(struct crypt_config *cc);
	int (*init)(struct crypt_config *cc);
	int (*wipe)(struct crypt_config *cc);
	int (*generator)(struct crypt_config *cc, u8 *iv,
			struct dm_crypt_request *dmreq);
	int (*post)(struct crypt_config *cc, u8 *iv,
			struct dm_crypt_request *dmreq);
};

/*
 * Crypt: maps a linear range of a block device
 * and encrypts / decrypts at the same time.
 */
enum flags { DM_CRYPT_SUSPENDED, DM_CRYPT_KEY_VALID,
	DM_CRYPT_SAME_CPU, DM_CRYPT_NO_OFFLOAD,
	DM_CRYPT_NO_READ_WORKQUEUE, DM_CRYPT_NO_WRITE_WORKQUEUE,
	DM_CRYPT_WRITE_INLINE, DM_CRYPT_STORE_DATA_IN_INTEGRITY_MD};

enum cipher_flags {
	CRYPT_MODE_INTEGRITY_AEAD,	/* Use authenticated mode for cipher */
	CRYPT_IV_LARGE_SECTORS,		/* Calculate IV from sector_size, not 512B sectors */
	CRYPT_ENCRYPT_PREPROCESS,	/* Must preprocess data for encryption (elephant) */
};


#define MIN_IOS		64
#define MAX_TAG_SIZE	480
#define POOL_ENTRY_SIZE	512

#define IV_SIZE 16
#define SECTOR_NUM_LEN	   4
#define SEQUENCE_NUMBER_LEN	2
#define PD_MAGIC_DATA		0xAA
#define PD_MAGIC_DATA_LEN 1 
#define PD_MAGIC_DATA_POS (IV_SIZE - PD_MAGIC_DATA_LEN) 
#define RANDOM_BYTES_PER_TAG 2
#define RANDOM_BYTES_POS (IV_SIZE - PD_MAGIC_DATA_LEN - RANDOM_BYTES_PER_TAG) 
#define IV_OFFSET_LEN 1
#define IV_OFFSET_POS (IV_SIZE - PD_MAGIC_DATA_LEN - RANDOM_BYTES_PER_TAG - IV_OFFSET_LEN)
#define CHUNK_NUM_SECTORS 32768 
#define HIDDEN_BYTES_IN_FIRST_IV (IV_SIZE - PD_MAGIC_DATA_LEN - RANDOM_BYTES_PER_TAG - IV_OFFSET_LEN - SEQUENCE_NUMBER_LEN - SECTOR_NUM_LEN) //6
#define HIDDEN_BYTES_IN_REST_IVS (IV_SIZE - PD_MAGIC_DATA_LEN - RANDOM_BYTES_PER_TAG - IV_OFFSET_LEN - SEQUENCE_NUMBER_LEN)  //10
#define NUM_PUBLIC_SECTORS_PER_HIDDEN_SECTOR 52 // ( 1 + (512 - HIDDEN_BYTES_IN_FIRST_IV) /HIDDEN_BYTES_IN_REST_IVS)
#define REUSE_PHYSICAL_BIT 48

static DEFINE_SPINLOCK(dm_crypt_clients_lock);
static unsigned dm_crypt_clients_n = 0;
static volatile unsigned long dm_crypt_pages_per_client;
#define DM_CRYPT_MEMORY_PERCENT			2
#define DM_CRYPT_MIN_PAGES_PER_CLIENT		(BIO_MAX_VECS * 16)

static void crypt_endio(struct bio *clone);
static void kcryptd_queue_crypt(struct dm_crypt_io *io);
static struct scatterlist *crypt_get_sg_data(struct crypt_config *cc,
		struct scatterlist *sg);
static void kcryptd_crypt_write_io_submit(struct dm_crypt_io *io, int async);
static void kcryptd_io_rdwr_map(struct dm_crypt_io *io);

static bool crypt_integrity_aead(struct crypt_config *cc);

struct file *bio_file = NULL;
extern void get_map_data(sector_t sector, char *tag, int tag_size, unsigned *max_sectors);
static void process_map_data(struct crypt_config *cc);
static void get_ivs_from_sector(struct dm_crypt_io *io, sector_t sector, unsigned char *tag, int tag_size);
static int read_sector_metadata(struct dm_crypt_io *io, struct bio *base_bio, sector_t sector, unsigned char *data, unsigned size);

#define printk(f_, ...) 

void print_integrity_metadata(char *msg, char *data)
{
	char str[200] = {0};
	int i;

	if (data != NULL)
	{
		for (i = 0; i < 48; i++)
		{
			sprintf(str + strlen(str), "%02hhx ", data[i]);
			//printk("%02hhx ", data[i]);
		}
		printk("%s, metadata - %s\n", msg, str);
	}
}

char *print_binary_data(char *data, int len)
{
	char *str = kmalloc(3 * len + 1, GFP_KERNEL);
	int i;

	memset(str, 0, 3 * len + 1);
	if (data != NULL)
	{
		for (i = 0; i < len; i++)
		{
			sprintf(str + strlen(str), "%02hhx ", data[i]);
		}
	}
	return(str);
}

struct file *file_open(const char *path, int flags, int rights)
{
	struct file *filp = NULL;
	int err = 0;

	filp = filp_open(path, flags, rights);
	if (IS_ERR(filp)) {
		err = PTR_ERR(filp);
		printk("Error opening %s, %d\n", path, err);
		return NULL;
	}
	return filp;
}


void file_close(struct file *file)
{
	filp_close(file, NULL);
}

void print_bio(char *msg, struct bio *bio)
{
	struct bvec_iter iter_out = bio->bi_iter;
	int count = 0;
	char *str;		
	char *p = NULL;

	if (!bio_file) {
		printk("bio_file not open\n");
		return;
	}

	printk("print_bio, %p, %s, size %d, starting sector %d, num of sectors %d\n", bio_file, msg, iter_out.bi_size, iter_out.bi_sector, bio_sectors(bio));
	p = kasprintf(GFP_KERNEL, "\n\nprint_bio, %s, total bio size %d, starting sector %d, num of sectors %d\n", msg, iter_out.bi_size, iter_out.bi_sector, bio_sectors(bio));
	kernel_write(bio_file, p, strlen(p), &bio_file->f_pos); 
	while (iter_out.bi_size) {
		p = kasprintf(GFP_KERNEL, "\nremaining size %d, current sector %d\n", iter_out.bi_size, iter_out.bi_sector);
		kernel_write(bio_file, p, strlen(p), &bio_file->f_pos); 
		unsigned size = min_t(unsigned, 512, iter_out.bi_size);
		struct bio_vec bv_out = bio_iter_iovec(bio, iter_out);
		char *buffer = page_to_virt(bv_out.bv_page);
		str = print_binary_data(buffer + bv_out.bv_offset, size);
		kernel_write(bio_file, str, strlen(str), &bio_file->f_pos);
		kfree(str);
		bio_advance_iter(bio, &iter_out, size);
		if (++count >= 6)
			break;
	}
	if (p)
		kfree(p);
}


typedef struct dirty_public_list {
	sector_t sector;
	struct dirty_public_list *next;
}dirty_public_list;

struct dirty_public_list *head_dirtylist = NULL;
struct dirty_public_list *tail_dirtylist = NULL;

bool findin_dirty_list(sector_t sector)
{
        struct dirty_public_list *temp = head_dirtylist;

        while(temp) {
		//printk("Dirty List input sector %d, has sector %d\n", sector, temp->sector);
                if (temp->sector == sector)
                        return true;
		temp = temp->next;
        }
        return false;
}

void removefrom_dirty_list(sector_t sector)
{
        struct dirty_public_list *temp = head_dirtylist;
        struct dirty_public_list *prev = head_dirtylist;

        while(temp) {
                //printk("Dirty List input sector %d, has sector %d\n", sector, temp->sector);
                if (temp->sector == sector) {
			if (temp == head_dirtylist)
				head_dirtylist = head_dirtylist->next;
			prev->next = temp->next;
			kfree(temp);
			return;
		}
		prev = temp;
                temp = temp->next;
        }
}

void addto_dirty_list(sector_t sector)
{
        //printk("dirty_public_list entry, inserting %d", sector);
	if (findin_dirty_list(sector))
		return;
        struct dirty_public_list *node = kmalloc(sizeof(struct dirty_public_list), GFP_KERNEL);
        node->sector = sector;
        node->next = NULL;

        if (head_dirtylist == NULL) {
                head_dirtylist = tail_dirtylist = node;
                return;
        }
	tail_dirtylist->next = node;
	tail_dirtylist = node;
}

struct freelist {
	unsigned sector;
	struct freelist *next;
};

struct freelist *head_freelist = NULL;
struct freelist *tail_freelist = NULL;
unsigned total_freelist = 0;

void addto_freelist(unsigned sector)
{
	struct freelist *temp, *prev;
	//printk("addto_freelist entry, inserting %d", sector);
	struct freelist *node = kmalloc(sizeof(struct freelist), GFP_KERNEL);
	node->sector = sector;
	node->next = NULL;

	//LOCK
	if (head_freelist == NULL) {
		//printk("addto_freelist head=tail=NULL");
		head_freelist = tail_freelist = node;
		goto unlock;
	}
	if (sector < head_freelist->sector) {
		node->next = head_freelist;
		head_freelist = node;
		//printk("addto_freelist inserting value less than head");
		goto unlock;
	}
	temp = prev = head_freelist;
	while(temp != NULL) {
		if(sector < temp->sector)
			break;
		if(sector == temp->sector) {
			//printk("addto_freelist sector %d already exists in freelist, total elements in freelist %d\n", sector, total_freelist);
			kfree(node);
			return;
		}
		prev = temp;
		temp = temp->next;
	}
	node->next = temp;
	prev->next = node;
unlock:
	total_freelist++;
	//printk("addto_freelist, added %d, total elements in freelist %d\n", sector, total_freelist);
	//printk("============================");
	//UNLOCK
	return;
}

void print_freelist(void )
{
	struct freelist *temp = head_freelist;
	int i = 0;
	printk("Inside print_freelist total elements %d", total_freelist);
	while(temp) {
		printk("Entry at %d, %d\n", i, temp->sector);
		i++;
		temp = temp->next;
	}
}

int getfrom_freelist(int sector_count, struct freelist_results *results)
{
	//LOCK
	if (!head_freelist || !total_freelist) {
		return -1;
	}
	//printk("getfrom_freelist, requested %d sectors from total of %d, head is %p\n", sector_count, total_freelist, head_freelist);
	struct freelist *temp = head_freelist;
	struct freelist *next = temp->next;
	struct freelist *temp_prev = NULL;
	struct freelist *prev = head_freelist;
	unsigned current_sector_count = 0;
	int count = 1;

	//iterate through the list and find n contiguous sectors
	while(temp != NULL && next != NULL) {
		if (next->sector != temp->sector + count) {
			temp = prev = next;
			temp_prev = prev;
			next = temp->next;
			count = 1;
			continue;
		}   
		prev = next;
		next = next->next;
		count++;
		if (count == sector_count)
			break;
	}   
	//printk("getfrom_freelist, while completed, requested %d sectors, got %d, from total of %d\n", sector_count, count, total_freelist);
	if(count != sector_count) {
		//printk("getfrom_freelist, found only %d free contiguous sectors out of required %d sectors. total sectors %d\n", count, sector_count, total_freelist);
		return -1; 
	}   
	else {
		//printk("getfrom_freelist, count %d, total %d, start %d, temp %p, temp_prev %p, temp_next %p, head %p", 
		//		sector_count, total_freelist, temp->sector, temp, temp_prev, temp->next, head_freelist);
		results[0].start = temp->sector;
		results[0].len = count;

		// remove alloted nodes from freelist
		prev = temp;
		temp = temp->next;
		while(prev != next) {
			kfree(prev);
			prev = temp;
			if (temp)
				temp = temp->next;
		}
		if (temp_prev)
			temp_prev->next = next;
		else
			head_freelist = next; //move the head pointer
		total_freelist -= sector_count;
		//printk("getfrom_freelist, returning %p", head_freelist);
		//printk("=========================");
		return 0;
	}
}

/*
 * Use this to access cipher attributes that are independent of the key.
 */
static struct crypto_skcipher *any_tfm(struct crypt_config *cc)
{
	return cc->cipher_tfm.tfms[0];
}

static struct crypto_aead *any_tfm_aead(struct crypt_config *cc)
{
	return cc->cipher_tfm.tfms_aead[0];
}

/*
 * Different IV generation algorithms:
 *
 * plain: the initial vector is the 32-bit little-endian version of the sector
 *		number, padded with zeros if necessary.
 *
 * plain64: the initial vector is the 64-bit little-endian version of the sector
 *		number, padded with zeros if necessary.
 *
 * plain64be: the initial vector is the 64-bit big-endian version of the sector
 *		number, padded with zeros if necessary.
 *
 * essiv: "encrypted sector|salt initial vector", the sector number is
 *		encrypted with the bulk cipher using a salt as key. The salt
 *		should be derived from the bulk cipher's key via hashing.
 *
 * benbi: the 64-bit "big-endian 'narrow block'-count", starting at 1
 *		(needed for LRW-32-AES and possible other narrow block modes)
 *
 * null: the initial vector is always zero.  Provides compatibility with
 *	   obsolete loop_fish2 devices.  Do not use for new devices.
 *
 * lmk:  Compatible implementation of the block chaining mode used
 *	   by the Loop-AES block device encryption system
 *	   designed by Jari Ruusu. See http://loop-aes.sourceforge.net/
 *	   It operates on full 512 byte sectors and uses CBC
 *	   with an IV derived from the sector number, the data and
 *	   optionally extra IV seed.
 *	   This means that after decryption the first block
 *	   of sector must be tweaked according to decrypted data.
 *	   Loop-AES can use three encryption schemes:
 *		 version 1: is plain aes-cbc mode
 *		 version 2: uses 64 multikey scheme with lmk IV generator
 *		 version 3: the same as version 2 with additional IV seed
 *				   (it uses 65 keys, last key is used as IV seed)
 *
 * tcw:  Compatible implementation of the block chaining mode used
 *	   by the TrueCrypt device encryption system (prior to version 4.1).
 *	   For more info see: https://gitlab.com/cryptsetup/cryptsetup/wikis/TrueCryptOnDiskFormat
 *	   It operates on full 512 byte sectors and uses CBC
 *	   with an IV derived from initial key and the sector number.
 *	   In addition, whitening value is applied on every sector, whitening
 *	   is calculated from initial key, sector number and mixed using CRC32.
 *	   Note that this encryption scheme is vulnerable to watermarking attacks
 *	   and should be used for old compatible containers access only.
 *
 * eboiv: Encrypted byte-offset IV (used in Bitlocker in CBC mode)
 *		The IV is encrypted little-endian byte-offset (with the same key
 *		and cipher as the volume).
 *
 * elephant: The extended version of eboiv with additional Elephant diffuser
 *		   used with Bitlocker CBC mode.
 *		   This mode was used in older Windows systems
 *		   https://download.microsoft.com/download/0/2/3/0238acaf-d3bf-4a6d-b3d6-0a0be4bbb36e/bitlockercipher200608.pdf
 */

static int crypt_iv_plain_gen(struct crypt_config *cc, u8 *iv,
		struct dm_crypt_request *dmreq)
{
	memset(iv, 0, cc->iv_size);
	*(__le32 *)iv = cpu_to_le32(dmreq->iv_sector & 0xffffffff);

	return 0;
}

static int crypt_iv_plain64_gen(struct crypt_config *cc, u8 *iv,
		struct dm_crypt_request *dmreq)
{
	memset(iv, 0, cc->iv_size);
	*(__le64 *)iv = cpu_to_le64(dmreq->iv_sector);

	return 0;
}

static int crypt_iv_plain64be_gen(struct crypt_config *cc, u8 *iv,
		struct dm_crypt_request *dmreq)
{
	memset(iv, 0, cc->iv_size);
	/* iv_size is at least of size u64; usually it is 16 bytes */
	*(__be64 *)&iv[cc->iv_size - sizeof(u64)] = cpu_to_be64(dmreq->iv_sector);

	return 0;
}

static int crypt_iv_essiv_gen(struct crypt_config *cc, u8 *iv,
		struct dm_crypt_request *dmreq)
{
	/*
	 * ESSIV encryption of the IV is now handled by the crypto API,
	 * so just pass the plain sector number here.
	 */
	memset(iv, 0, cc->iv_size);
	*(__le64 *)iv = cpu_to_le64(dmreq->iv_sector);

	return 0;
}

static int crypt_iv_benbi_ctr(struct crypt_config *cc, struct dm_target *ti,
		const char *opts)
{
	unsigned bs;
	int log;

	if (crypt_integrity_aead(cc))
		bs = crypto_aead_blocksize(any_tfm_aead(cc));
	else
		bs = crypto_skcipher_blocksize(any_tfm(cc));
	log = ilog2(bs);

	/* we need to calculate how far we must shift the sector count
	 * to get the cipher block count, we use this shift in _gen */

	if (1 << log != bs) {
		ti->error = "cypher blocksize is not a power of 2";
		return -EINVAL;
	}

	if (log > 9) {
		ti->error = "cypher blocksize is > 512";
		return -EINVAL;
	}

	cc->iv_gen_private.benbi.shift = 9 - log;

	return 0;
}

static void crypt_iv_benbi_dtr(struct crypt_config *cc)
{
}

static int crypt_iv_benbi_gen(struct crypt_config *cc, u8 *iv,
		struct dm_crypt_request *dmreq)
{
	__be64 val;

	memset(iv, 0, cc->iv_size - sizeof(u64)); /* rest is cleared below */

	val = cpu_to_be64(((u64)dmreq->iv_sector << cc->iv_gen_private.benbi.shift) + 1);
	put_unaligned(val, (__be64 *)(iv + cc->iv_size - sizeof(u64)));

	return 0;
}

static int crypt_iv_null_gen(struct crypt_config *cc, u8 *iv,
		struct dm_crypt_request *dmreq)
{
	memset(iv, 0, cc->iv_size);

	return 0;
}

static void crypt_iv_lmk_dtr(struct crypt_config *cc)
{
	struct iv_lmk_private *lmk = &cc->iv_gen_private.lmk;

	if (lmk->hash_tfm && !IS_ERR(lmk->hash_tfm))
		crypto_free_shash(lmk->hash_tfm);
	lmk->hash_tfm = NULL;

	kfree_sensitive(lmk->seed);
	lmk->seed = NULL;
}

static int crypt_iv_lmk_ctr(struct crypt_config *cc, struct dm_target *ti,
		const char *opts)
{
	struct iv_lmk_private *lmk = &cc->iv_gen_private.lmk;

	if (cc->sector_size != (1 << SECTOR_SHIFT)) {
		ti->error = "Unsupported sector size for LMK";
		return -EINVAL;
	}

	lmk->hash_tfm = crypto_alloc_shash("md5", 0,
			CRYPTO_ALG_ALLOCATES_MEMORY);
	if (IS_ERR(lmk->hash_tfm)) {
		ti->error = "Error initializing LMK hash";
		return PTR_ERR(lmk->hash_tfm);
	}

	/* No seed in LMK version 2 */
	if (cc->key_parts == cc->tfms_count) {
		lmk->seed = NULL;
		return 0;
	}

	lmk->seed = kzalloc(LMK_SEED_SIZE, GFP_KERNEL);
	if (!lmk->seed) {
		crypt_iv_lmk_dtr(cc);
		ti->error = "Error kmallocing seed storage in LMK";
		return -ENOMEM;
	}

	return 0;
}

static int crypt_iv_lmk_init(struct crypt_config *cc)
{
	struct iv_lmk_private *lmk = &cc->iv_gen_private.lmk;
	int subkey_size = cc->key_size / cc->key_parts;

	/* LMK seed is on the position of LMK_KEYS + 1 key */
	if (lmk->seed)
		memcpy(lmk->seed, cc->key + (cc->tfms_count * subkey_size),
				crypto_shash_digestsize(lmk->hash_tfm));

	return 0;
}

static int crypt_iv_lmk_wipe(struct crypt_config *cc)
{
	struct iv_lmk_private *lmk = &cc->iv_gen_private.lmk;

	if (lmk->seed)
		memset(lmk->seed, 0, LMK_SEED_SIZE);

	return 0;
}

static int crypt_iv_lmk_one(struct crypt_config *cc, u8 *iv,
		struct dm_crypt_request *dmreq,
		u8 *data)
{
	struct iv_lmk_private *lmk = &cc->iv_gen_private.lmk;
	SHASH_DESC_ON_STACK(desc, lmk->hash_tfm);
	struct md5_state md5state;
	__le32 buf[4];
	int i, r;

	desc->tfm = lmk->hash_tfm;

	r = crypto_shash_init(desc);
	if (r)
		return r;

	if (lmk->seed) {
		r = crypto_shash_update(desc, lmk->seed, LMK_SEED_SIZE);
		if (r)
			return r;
	}

	/* Sector is always 512B, block size 16, add data of blocks 1-31 */
	r = crypto_shash_update(desc, data + 16, 16 * 31);
	if (r)
		return r;

	/* Sector is cropped to 56 bits here */
	buf[0] = cpu_to_le32(dmreq->iv_sector & 0xFFFFFFFF);
	buf[1] = cpu_to_le32((((u64)dmreq->iv_sector >> 32) & 0x00FFFFFF) | 0x80000000);
	buf[2] = cpu_to_le32(4024);
	buf[3] = 0;
	r = crypto_shash_update(desc, (u8 *)buf, sizeof(buf));
	if (r)
		return r;

	/* No MD5 padding here */
	r = crypto_shash_export(desc, &md5state);
	if (r)
		return r;

	for (i = 0; i < MD5_HASH_WORDS; i++)
		__cpu_to_le32s(&md5state.hash[i]);
	memcpy(iv, &md5state.hash, cc->iv_size);

	return 0;
}

static int crypt_iv_lmk_gen(struct crypt_config *cc, u8 *iv,
		struct dm_crypt_request *dmreq)
{
	struct scatterlist *sg;
	u8 *src;
	int r = 0;

	if (bio_data_dir(dmreq->ctx->bio_in) == WRITE) {
		sg = crypt_get_sg_data(cc, dmreq->sg_in);
		src = kmap_atomic(sg_page(sg));
		r = crypt_iv_lmk_one(cc, iv, dmreq, src + sg->offset);
		kunmap_atomic(src);
	} else
		memset(iv, 0, cc->iv_size);

	return r;
}

static int crypt_iv_lmk_post(struct crypt_config *cc, u8 *iv,
		struct dm_crypt_request *dmreq)
{
	struct scatterlist *sg;
	u8 *dst;
	int r;

	if (bio_data_dir(dmreq->ctx->bio_in) == WRITE)
		return 0;

	sg = crypt_get_sg_data(cc, dmreq->sg_out);
	dst = kmap_atomic(sg_page(sg));
	r = crypt_iv_lmk_one(cc, iv, dmreq, dst + sg->offset);

	/* Tweak the first block of plaintext sector */
	if (!r)
		crypto_xor(dst + sg->offset, iv, cc->iv_size);

	kunmap_atomic(dst);
	return r;
}

static void crypt_iv_tcw_dtr(struct crypt_config *cc)
{
	struct iv_tcw_private *tcw = &cc->iv_gen_private.tcw;

	kfree_sensitive(tcw->iv_seed);
	tcw->iv_seed = NULL;
	kfree_sensitive(tcw->whitening);
	tcw->whitening = NULL;

	if (tcw->crc32_tfm && !IS_ERR(tcw->crc32_tfm))
		crypto_free_shash(tcw->crc32_tfm);
	tcw->crc32_tfm = NULL;
}

static int crypt_iv_tcw_ctr(struct crypt_config *cc, struct dm_target *ti,
		const char *opts)
{
	struct iv_tcw_private *tcw = &cc->iv_gen_private.tcw;

	if (cc->sector_size != (1 << SECTOR_SHIFT)) {
		ti->error = "Unsupported sector size for TCW";
		return -EINVAL;
	}

	if (cc->key_size <= (cc->iv_size + TCW_WHITENING_SIZE)) {
		ti->error = "Wrong key size for TCW";
		return -EINVAL;
	}

	tcw->crc32_tfm = crypto_alloc_shash("crc32", 0,
			CRYPTO_ALG_ALLOCATES_MEMORY);
	if (IS_ERR(tcw->crc32_tfm)) {
		ti->error = "Error initializing CRC32 in TCW";
		return PTR_ERR(tcw->crc32_tfm);
	}

	tcw->iv_seed = kzalloc(cc->iv_size, GFP_KERNEL);
	tcw->whitening = kzalloc(TCW_WHITENING_SIZE, GFP_KERNEL);
	if (!tcw->iv_seed || !tcw->whitening) {
		crypt_iv_tcw_dtr(cc);
		ti->error = "Error allocating seed storage in TCW";
		return -ENOMEM;
	}

	return 0;
}

static int crypt_iv_tcw_init(struct crypt_config *cc)
{
	struct iv_tcw_private *tcw = &cc->iv_gen_private.tcw;
	int key_offset = cc->key_size - cc->iv_size - TCW_WHITENING_SIZE;

	memcpy(tcw->iv_seed, &cc->key[key_offset], cc->iv_size);
	memcpy(tcw->whitening, &cc->key[key_offset + cc->iv_size],
			TCW_WHITENING_SIZE);

	return 0;
}

static int crypt_iv_tcw_wipe(struct crypt_config *cc)
{
	struct iv_tcw_private *tcw = &cc->iv_gen_private.tcw;

	memset(tcw->iv_seed, 0, cc->iv_size);
	memset(tcw->whitening, 0, TCW_WHITENING_SIZE);

	return 0;
}

static int crypt_iv_tcw_whitening(struct crypt_config *cc,
		struct dm_crypt_request *dmreq,
		u8 *data)
{
	struct iv_tcw_private *tcw = &cc->iv_gen_private.tcw;
	__le64 sector = cpu_to_le64(dmreq->iv_sector);
	u8 buf[TCW_WHITENING_SIZE];
	SHASH_DESC_ON_STACK(desc, tcw->crc32_tfm);
	int i, r;

	/* xor whitening with sector number */
	crypto_xor_cpy(buf, tcw->whitening, (u8 *)&sector, 8);
	crypto_xor_cpy(&buf[8], tcw->whitening + 8, (u8 *)&sector, 8);

	/* calculate crc32 for every 32bit part and xor it */
	desc->tfm = tcw->crc32_tfm;
	for (i = 0; i < 4; i++) {
		r = crypto_shash_init(desc);
		if (r)
			goto out;
		r = crypto_shash_update(desc, &buf[i * 4], 4);
		if (r)
			goto out;
		r = crypto_shash_final(desc, &buf[i * 4]);
		if (r)
			goto out;
	}
	crypto_xor(&buf[0], &buf[12], 4);
	crypto_xor(&buf[4], &buf[8], 4);

	/* apply whitening (8 bytes) to whole sector */
	for (i = 0; i < ((1 << SECTOR_SHIFT) / 8); i++)
		crypto_xor(data + i * 8, buf, 8);
out:
	memzero_explicit(buf, sizeof(buf));
	return r;
}

static int crypt_iv_tcw_gen(struct crypt_config *cc, u8 *iv,
		struct dm_crypt_request *dmreq)
{
	struct scatterlist *sg;
	struct iv_tcw_private *tcw = &cc->iv_gen_private.tcw;
	__le64 sector = cpu_to_le64(dmreq->iv_sector);
	u8 *src;
	int r = 0;

	/* Remove whitening from ciphertext */
	if (bio_data_dir(dmreq->ctx->bio_in) != WRITE) {
		sg = crypt_get_sg_data(cc, dmreq->sg_in);
		src = kmap_atomic(sg_page(sg));
		r = crypt_iv_tcw_whitening(cc, dmreq, src + sg->offset);
		kunmap_atomic(src);
	}

	/* Calculate IV */
	crypto_xor_cpy(iv, tcw->iv_seed, (u8 *)&sector, 8);
	if (cc->iv_size > 8)
		crypto_xor_cpy(&iv[8], tcw->iv_seed + 8, (u8 *)&sector,
				cc->iv_size - 8);

	return r;
}

static int crypt_iv_tcw_post(struct crypt_config *cc, u8 *iv,
		struct dm_crypt_request *dmreq)
{
	struct scatterlist *sg;
	u8 *dst;
	int r;

	if (bio_data_dir(dmreq->ctx->bio_in) != WRITE)
		return 0;

	/* Apply whitening on ciphertext */
	sg = crypt_get_sg_data(cc, dmreq->sg_out);
	dst = kmap_atomic(sg_page(sg));
	r = crypt_iv_tcw_whitening(cc, dmreq, dst + sg->offset);
	kunmap_atomic(dst);

	return r;
}

static int crypt_iv_random_gen(struct crypt_config *cc, u8 *iv,
		struct dm_crypt_request *dmreq)
{
	/* Used only for writes, there must be an additional space to store IV */
	get_random_bytes(iv, cc->iv_size);
	return 0;
}

static int crypt_iv_eboiv_ctr(struct crypt_config *cc, struct dm_target *ti,
		const char *opts)
{
	if (crypt_integrity_aead(cc)) {
		ti->error = "AEAD transforms not supported for EBOIV";
		return -EINVAL;
	}

	if (crypto_skcipher_blocksize(any_tfm(cc)) != cc->iv_size) {
		ti->error = "Block size of EBOIV cipher does "
			"not match IV size of block cipher";
		return -EINVAL;
	}

	return 0;
}

static int crypt_iv_eboiv_gen(struct crypt_config *cc, u8 *iv,
		struct dm_crypt_request *dmreq)
{
	u8 buf[MAX_CIPHER_BLOCKSIZE] __aligned(__alignof__(__le64));
	struct skcipher_request *req;
	struct scatterlist src, dst;
	DECLARE_CRYPTO_WAIT(wait);
	int err;

	req = skcipher_request_alloc(any_tfm(cc), GFP_NOIO);
	if (!req)
		return -ENOMEM;

	memset(buf, 0, cc->iv_size);
	*(__le64 *)buf = cpu_to_le64(dmreq->iv_sector * cc->sector_size);

	sg_init_one(&src, page_address(ZERO_PAGE(0)), cc->iv_size);
	sg_init_one(&dst, iv, cc->iv_size);
	skcipher_request_set_crypt(req, &src, &dst, cc->iv_size, buf);
	skcipher_request_set_callback(req, 0, crypto_req_done, &wait);
	err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
	skcipher_request_free(req);

	return err;
}

static void crypt_iv_elephant_dtr(struct crypt_config *cc)
{
	struct iv_elephant_private *elephant = &cc->iv_gen_private.elephant;

	crypto_free_skcipher(elephant->tfm);
	elephant->tfm = NULL;
}

static int crypt_iv_elephant_ctr(struct crypt_config *cc, struct dm_target *ti,
		const char *opts)
{
	struct iv_elephant_private *elephant = &cc->iv_gen_private.elephant;
	int r;

	elephant->tfm = crypto_alloc_skcipher("ecb(aes)", 0,
			CRYPTO_ALG_ALLOCATES_MEMORY);
	if (IS_ERR(elephant->tfm)) {
		r = PTR_ERR(elephant->tfm);
		elephant->tfm = NULL;
		return r;
	}

	r = crypt_iv_eboiv_ctr(cc, ti, NULL);
	if (r)
		crypt_iv_elephant_dtr(cc);
	return r;
}

static void diffuser_disk_to_cpu(u32 *d, size_t n)
{
#ifndef __LITTLE_ENDIAN
	int i;

	for (i = 0; i < n; i++)
		d[i] = le32_to_cpu((__le32)d[i]);
#endif
}

static void diffuser_cpu_to_disk(__le32 *d, size_t n)
{
#ifndef __LITTLE_ENDIAN
	int i;

	for (i = 0; i < n; i++)
		d[i] = cpu_to_le32((u32)d[i]);
#endif
}

static void diffuser_a_decrypt(u32 *d, size_t n)
{
	int i, i1, i2, i3;

	for (i = 0; i < 5; i++) {
		i1 = 0;
		i2 = n - 2;
		i3 = n - 5;

		while (i1 < (n - 1)) {
			d[i1] += d[i2] ^ (d[i3] << 9 | d[i3] >> 23);
			i1++; i2++; i3++;

			if (i3 >= n)
				i3 -= n;

			d[i1] += d[i2] ^ d[i3];
			i1++; i2++; i3++;

			if (i2 >= n)
				i2 -= n;

			d[i1] += d[i2] ^ (d[i3] << 13 | d[i3] >> 19);
			i1++; i2++; i3++;

			d[i1] += d[i2] ^ d[i3];
			i1++; i2++; i3++;
		}
	}
}

static void diffuser_a_encrypt(u32 *d, size_t n)
{
	int i, i1, i2, i3;

	for (i = 0; i < 5; i++) {
		i1 = n - 1;
		i2 = n - 2 - 1;
		i3 = n - 5 - 1;

		while (i1 > 0) {
			d[i1] -= d[i2] ^ d[i3];
			i1--; i2--; i3--;

			d[i1] -= d[i2] ^ (d[i3] << 13 | d[i3] >> 19);
			i1--; i2--; i3--;

			if (i2 < 0)
				i2 += n;

			d[i1] -= d[i2] ^ d[i3];
			i1--; i2--; i3--;

			if (i3 < 0)
				i3 += n;

			d[i1] -= d[i2] ^ (d[i3] << 9 | d[i3] >> 23);
			i1--; i2--; i3--;
		}
	}
}

static void diffuser_b_decrypt(u32 *d, size_t n)
{
	int i, i1, i2, i3;

	for (i = 0; i < 3; i++) {
		i1 = 0;
		i2 = 2;
		i3 = 5;

		while (i1 < (n - 1)) {
			d[i1] += d[i2] ^ d[i3];
			i1++; i2++; i3++;

			d[i1] += d[i2] ^ (d[i3] << 10 | d[i3] >> 22);
			i1++; i2++; i3++;

			if (i2 >= n)
				i2 -= n;

			d[i1] += d[i2] ^ d[i3];
			i1++; i2++; i3++;

			if (i3 >= n)
				i3 -= n;

			d[i1] += d[i2] ^ (d[i3] << 25 | d[i3] >> 7);
			i1++; i2++; i3++;
		}
	}
}

static void diffuser_b_encrypt(u32 *d, size_t n)
{
	int i, i1, i2, i3;

	for (i = 0; i < 3; i++) {
		i1 = n - 1;
		i2 = 2 - 1;
		i3 = 5 - 1;

		while (i1 > 0) {
			d[i1] -= d[i2] ^ (d[i3] << 25 | d[i3] >> 7);
			i1--; i2--; i3--;

			if (i3 < 0)
				i3 += n;

			d[i1] -= d[i2] ^ d[i3];
			i1--; i2--; i3--;

			if (i2 < 0)
				i2 += n;

			d[i1] -= d[i2] ^ (d[i3] << 10 | d[i3] >> 22);
			i1--; i2--; i3--;

			d[i1] -= d[i2] ^ d[i3];
			i1--; i2--; i3--;
		}
	}
}

static int crypt_iv_elephant(struct crypt_config *cc, struct dm_crypt_request *dmreq)
{
	struct iv_elephant_private *elephant = &cc->iv_gen_private.elephant;
	u8 *es, *ks, *data, *data2, *data_offset;
	struct skcipher_request *req;
	struct scatterlist *sg, *sg2, src, dst;
	DECLARE_CRYPTO_WAIT(wait);
	int i, r;

	req = skcipher_request_alloc(elephant->tfm, GFP_NOIO);
	es = kzalloc(16, GFP_NOIO); /* Key for AES */
	ks = kzalloc(32, GFP_NOIO); /* Elephant sector key */

	if (!req || !es || !ks) {
		r = -ENOMEM;
		goto out;
	}

	*(__le64 *)es = cpu_to_le64(dmreq->iv_sector * cc->sector_size);

	/* E(Ks, e(s)) */
	sg_init_one(&src, es, 16);
	sg_init_one(&dst, ks, 16);
	skcipher_request_set_crypt(req, &src, &dst, 16, NULL);
	skcipher_request_set_callback(req, 0, crypto_req_done, &wait);
	r = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
	if (r)
		goto out;

	/* E(Ks, e'(s)) */
	es[15] = 0x80;
	sg_init_one(&dst, &ks[16], 16);
	r = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
	if (r)
		goto out;

	sg = crypt_get_sg_data(cc, dmreq->sg_out);
	data = kmap_atomic(sg_page(sg));
	data_offset = data + sg->offset;

	/* Cannot modify original bio, copy to sg_out and apply Elephant to it */
	if (bio_data_dir(dmreq->ctx->bio_in) == WRITE) {
		sg2 = crypt_get_sg_data(cc, dmreq->sg_in);
		data2 = kmap_atomic(sg_page(sg2));
		memcpy(data_offset, data2 + sg2->offset, cc->sector_size);
		kunmap_atomic(data2);
	}

	if (bio_data_dir(dmreq->ctx->bio_in) != WRITE) {
		diffuser_disk_to_cpu((u32*)data_offset, cc->sector_size / sizeof(u32));
		diffuser_b_decrypt((u32*)data_offset, cc->sector_size / sizeof(u32));
		diffuser_a_decrypt((u32*)data_offset, cc->sector_size / sizeof(u32));
		diffuser_cpu_to_disk((__le32*)data_offset, cc->sector_size / sizeof(u32));
	}

	for (i = 0; i < (cc->sector_size / 32); i++)
		crypto_xor(data_offset + i * 32, ks, 32);

	if (bio_data_dir(dmreq->ctx->bio_in) == WRITE) {
		diffuser_disk_to_cpu((u32*)data_offset, cc->sector_size / sizeof(u32));
		diffuser_a_encrypt((u32*)data_offset, cc->sector_size / sizeof(u32));
		diffuser_b_encrypt((u32*)data_offset, cc->sector_size / sizeof(u32));
		diffuser_cpu_to_disk((__le32*)data_offset, cc->sector_size / sizeof(u32));
	}

	kunmap_atomic(data);
out:
	kfree_sensitive(ks);
	kfree_sensitive(es);
	skcipher_request_free(req);
	return r;
}

static int crypt_iv_elephant_gen(struct crypt_config *cc, u8 *iv,
		struct dm_crypt_request *dmreq)
{
	int r;

	if (bio_data_dir(dmreq->ctx->bio_in) == WRITE) {
		r = crypt_iv_elephant(cc, dmreq);
		if (r)
			return r;
	}

	return crypt_iv_eboiv_gen(cc, iv, dmreq);
}

static int crypt_iv_elephant_post(struct crypt_config *cc, u8 *iv,
		struct dm_crypt_request *dmreq)
{
	if (bio_data_dir(dmreq->ctx->bio_in) != WRITE)
		return crypt_iv_elephant(cc, dmreq);

	return 0;
}

static int crypt_iv_elephant_init(struct crypt_config *cc)
{
	struct iv_elephant_private *elephant = &cc->iv_gen_private.elephant;
	int key_offset = cc->key_size - cc->key_extra_size;

	return crypto_skcipher_setkey(elephant->tfm, &cc->key[key_offset], cc->key_extra_size);
}

static int crypt_iv_elephant_wipe(struct crypt_config *cc)
{
	struct iv_elephant_private *elephant = &cc->iv_gen_private.elephant;
	u8 key[ELEPHANT_MAX_KEY_SIZE];

	memset(key, 0, cc->key_extra_size);
	return crypto_skcipher_setkey(elephant->tfm, key, cc->key_extra_size);
}

static const struct crypt_iv_operations crypt_iv_plain_ops = {
	.generator = crypt_iv_plain_gen
};

static const struct crypt_iv_operations crypt_iv_plain64_ops = {
	.generator = crypt_iv_plain64_gen
};

static const struct crypt_iv_operations crypt_iv_plain64be_ops = {
	.generator = crypt_iv_plain64be_gen
};

static const struct crypt_iv_operations crypt_iv_essiv_ops = {
	.generator = crypt_iv_essiv_gen
};

static const struct crypt_iv_operations crypt_iv_benbi_ops = {
	.ctr	   = crypt_iv_benbi_ctr,
	.dtr	   = crypt_iv_benbi_dtr,
	.generator = crypt_iv_benbi_gen
};

static const struct crypt_iv_operations crypt_iv_null_ops = {
	.generator = crypt_iv_null_gen
};

static const struct crypt_iv_operations crypt_iv_lmk_ops = {
	.ctr	   = crypt_iv_lmk_ctr,
	.dtr	   = crypt_iv_lmk_dtr,
	.init	   = crypt_iv_lmk_init,
	.wipe	   = crypt_iv_lmk_wipe,
	.generator = crypt_iv_lmk_gen,
	.post	   = crypt_iv_lmk_post
};

static const struct crypt_iv_operations crypt_iv_tcw_ops = {
	.ctr	   = crypt_iv_tcw_ctr,
	.dtr	   = crypt_iv_tcw_dtr,
	.init	   = crypt_iv_tcw_init,
	.wipe	   = crypt_iv_tcw_wipe,
	.generator = crypt_iv_tcw_gen,
	.post	   = crypt_iv_tcw_post
};

static const struct crypt_iv_operations crypt_iv_random_ops = {
	.generator = crypt_iv_random_gen
};

static const struct crypt_iv_operations crypt_iv_eboiv_ops = {
	.ctr	   = crypt_iv_eboiv_ctr,
	.generator = crypt_iv_eboiv_gen
};

static const struct crypt_iv_operations crypt_iv_elephant_ops = {
	.ctr	   = crypt_iv_elephant_ctr,
	.dtr	   = crypt_iv_elephant_dtr,
	.init	   = crypt_iv_elephant_init,
	.wipe	   = crypt_iv_elephant_wipe,
	.generator = crypt_iv_elephant_gen,
	.post	   = crypt_iv_elephant_post
};

/*
 * Integrity extensions
 */
static bool crypt_integrity_aead(struct crypt_config *cc)
{
	return test_bit(CRYPT_MODE_INTEGRITY_AEAD, &cc->cipher_flags);
}

static bool crypt_integrity_hmac(struct crypt_config *cc)
{
	return crypt_integrity_aead(cc) && cc->key_mac_size;
}

/* Get sg containing data */
static struct scatterlist *crypt_get_sg_data(struct crypt_config *cc,
		struct scatterlist *sg)
{
	if (unlikely(crypt_integrity_aead(cc)))
		return &sg[2];

	return sg;
}

int dm_crypt_integrity_io_alloc(struct dm_crypt_io *io, struct bio *bio, int offset)
{
	struct bio_integrity_payload *bip;
	unsigned int tag_len;
	int ret;

	if (!bio_sectors(bio) || !io->cc->on_disk_tag_size)
		return 0;

	bip = bio_integrity_alloc(bio, GFP_NOIO, 1);
	if (IS_ERR(bip))
		return PTR_ERR(bip);

	tag_len = io->cc->on_disk_tag_size * (bio_sectors(bio) >> io->cc->sector_shift);
	//printk("Allocating bio_integrity_payload of size %d\n", tag_len);

	bip->bip_iter.bi_size = tag_len;
	bip->bip_iter.bi_sector = bio->bi_iter.bi_sector;

	ret = bio_integrity_add_page(bio, virt_to_page(io->integrity_metadata + offset),
			tag_len, offset_in_page(io->integrity_metadata + offset));
	if (unlikely(ret != tag_len))
		return -ENOMEM;

	return 0;
}

static int crypt_integrity_ctr(struct crypt_config *cc, struct dm_target *ti)
{
#ifdef CONFIG_BLK_DEV_INTEGRITY
	printk("Disk name is %s\n", cc->dev->bdev->bd_disk->disk_name);
	struct blk_integrity *bi = blk_get_integrity(cc->dev->bdev->bd_disk);
	struct mapped_device *md = dm_table_get_md(ti->table);

	/* From now we require underlying device with our integrity profile */
	if (!bi || strcasecmp(bi->profile->name, "DM-DIF-EXT-TAG")) {
		ti->error = "Integrity profile not supported.";
		if (bi)
			printk("integrity profile is %s\n",bi->profile->name);
		return -EINVAL;
	}

	if (bi->tag_size != cc->on_disk_tag_size ||
			bi->tuple_size != cc->on_disk_tag_size) {
		ti->error = "Integrity profile tag size mismatch.";
		return -EINVAL;
	}
	if (1 << bi->interval_exp != cc->sector_size) {
		ti->error = "Integrity profile sector size mismatch.";
		return -EINVAL;
	}

	printk("cc->integrity_iv_size is %d, blk_integrity %p\n", cc->integrity_iv_size, bi);
	if (bi)
		printk("bi profile %s\n", bi->profile->name);

	if (crypt_integrity_aead(cc)) {
		cc->integrity_tag_size = cc->on_disk_tag_size - cc->integrity_iv_size;
		printk("%s: Integrity AEAD, tag size %u, IV size %u.", dm_device_name(md),
				cc->integrity_tag_size, cc->integrity_iv_size);

		if (crypto_aead_setauthsize(any_tfm_aead(cc), cc->integrity_tag_size)) {
			ti->error = "Integrity AEAD auth tag size is not supported.";
			return -EINVAL;
		}
	} else if (cc->integrity_iv_size)
		printk("%s: Additional per-sector space %u bytes for IV.", dm_device_name(md),
				cc->integrity_iv_size);

	if ((cc->integrity_tag_size + cc->integrity_iv_size) != bi->tag_size) {
		ti->error = "Not enough space for integrity tag in the profile.";
		return -EINVAL;
	}

	return 0;
#else
	ti->error = "Integrity profile not supported.";
	return -EINVAL;
#endif
}

void crypt_convert_init(struct crypt_config *cc,
		struct convert_context *ctx,
		struct bio *bio_out, struct bio *bio_in,
		sector_t sector, unsigned int *tag_offset)
{
	struct dm_crypt_io *io = container_of(ctx, struct dm_crypt_io, ctx);
	ctx->bio_in = bio_in;
	ctx->bio_out = bio_out;
	if (bio_in)
		ctx->iter_in = bio_in->bi_iter;
	if (bio_out)
		ctx->iter_out = bio_out->bi_iter;
	ctx->cc_sector = sector + cc->iv_offset;
	ctx->tag_offset = tag_offset;
	if ((io->flags & PD_READ_DURING_HIDDEN_WRITE) || (io->flags & PD_READ_DURING_PUBLIC_WRITE)) 
		reinit_completion(&ctx->restart);
	else
		init_completion(&ctx->restart);


}

static struct dm_crypt_request *dmreq_of_req(struct crypt_config *cc,
		void *req)
{
	return (struct dm_crypt_request *)((char *)req + cc->dmreq_start);
}

static void *req_of_dmreq(struct crypt_config *cc, struct dm_crypt_request *dmreq)
{
	return (void *)((char *)dmreq - cc->dmreq_start);
}

static u8 *iv_of_dmreq(struct crypt_config *cc,
		struct dm_crypt_request *dmreq)
{
	if (crypt_integrity_aead(cc))
		return (u8 *)ALIGN((unsigned long)(dmreq + 1),
				crypto_aead_alignmask(any_tfm_aead(cc)) + 1);
	else
		return (u8 *)ALIGN((unsigned long)(dmreq + 1),
				crypto_skcipher_alignmask(any_tfm(cc)) + 1);
}

static u8 *org_iv_of_dmreq(struct crypt_config *cc,
		struct dm_crypt_request *dmreq)
{
	return iv_of_dmreq(cc, dmreq) + cc->iv_size;
}

static __le64 *org_sector_of_dmreq(struct crypt_config *cc,
		struct dm_crypt_request *dmreq)
{
	u8 *ptr = iv_of_dmreq(cc, dmreq) + cc->iv_size + cc->iv_size;
	return (__le64 *) ptr;
}

static unsigned int *org_tag_of_dmreq(struct crypt_config *cc,
		struct dm_crypt_request *dmreq)
{
	u8 *ptr = iv_of_dmreq(cc, dmreq) + cc->iv_size +
		cc->iv_size + sizeof(uint64_t);
	return (unsigned int*)ptr;
}

static void *tag_from_dmreq(struct crypt_config *cc,
		struct dm_crypt_request *dmreq)
{
	struct convert_context *ctx = dmreq->ctx;
	struct dm_crypt_io *io = container_of(ctx, struct dm_crypt_io, ctx);

	return &io->integrity_metadata[*org_tag_of_dmreq(cc, dmreq) *
		cc->on_disk_tag_size];
}

static void *iv_tag_from_dmreq(struct crypt_config *cc,
		struct dm_crypt_request *dmreq)
{
	return tag_from_dmreq(cc, dmreq) + cc->integrity_tag_size;
}

static int crypt_convert_block_aead(struct crypt_config *cc,
		struct convert_context *ctx,
		struct aead_request *req,
		unsigned int tag_offset)
{
	struct bio_vec bv_in = bio_iter_iovec(ctx->bio_in, ctx->iter_in);
	struct bio_vec bv_out = bio_iter_iovec(ctx->bio_out, ctx->iter_out);
	struct dm_crypt_request *dmreq;
	u8 *iv, *org_iv, *tag_iv, *tag;
	__le64 *sector;
	int r = 0;
	struct dm_crypt_io *io;

	BUG_ON(cc->integrity_iv_size && cc->integrity_iv_size != cc->iv_size);

	/* Reject unexpected unaligned bio. */
	if (unlikely(bv_in.bv_len & (cc->sector_size - 1)))
		return -EIO;

	dmreq = dmreq_of_req(cc, req);
	dmreq->iv_sector = ctx->cc_sector;
	if (test_bit(CRYPT_IV_LARGE_SECTORS, &cc->cipher_flags))
		dmreq->iv_sector >>= cc->sector_shift;
	dmreq->ctx = ctx;

	*org_tag_of_dmreq(cc, dmreq) = tag_offset;

	sector = org_sector_of_dmreq(cc, dmreq);
	*sector = cpu_to_le64(ctx->cc_sector - cc->iv_offset);

	iv = iv_of_dmreq(cc, dmreq);
	org_iv = org_iv_of_dmreq(cc, dmreq);
	tag = tag_from_dmreq(cc, dmreq);
	tag_iv = iv_tag_from_dmreq(cc, dmreq);

	io = container_of(ctx, struct dm_crypt_io, ctx);
	printk("Encrypting from %p, length %d, offset %d", bv_in.bv_page, cc->sector_size, bv_in.bv_offset);

	/* AEAD request:
	 *  |----- AAD -------|------ DATA -------|-- AUTH TAG --|
	 *  | (authenticated) | (auth+encryption) |			  |
	 *  | sector_LE |  IV |  sector in/out	|  tag in/out  |
	 */

	sg_init_table(dmreq->sg_in, 4);
	sg_set_buf(&dmreq->sg_in[0], sector, sizeof(uint64_t));
	sg_set_buf(&dmreq->sg_in[1], org_iv, cc->iv_size);
	sg_set_page(&dmreq->sg_in[2], bv_in.bv_page, cc->sector_size, bv_in.bv_offset);
	sg_set_buf(&dmreq->sg_in[3], tag, cc->integrity_tag_size);

	sg_init_table(dmreq->sg_out, 4);
	sg_set_buf(&dmreq->sg_out[0], sector, sizeof(uint64_t));
	sg_set_buf(&dmreq->sg_out[1], org_iv, cc->iv_size);
	sg_set_page(&dmreq->sg_out[2], bv_out.bv_page, cc->sector_size, bv_out.bv_offset);
	sg_set_buf(&dmreq->sg_out[3], tag, cc->integrity_tag_size);

	if (cc->iv_gen_ops) {
		/* For READs use IV stored in integrity metadata */
		if (cc->integrity_iv_size && bio_data_dir(ctx->bio_in) != WRITE) {
			memcpy(org_iv, tag_iv, cc->iv_size);
		} else {
			r = cc->iv_gen_ops->generator(cc, org_iv, dmreq);
			if (r < 0)
				return r;
			/* Store generated IV in integrity metadata */
			if (cc->integrity_iv_size)
				memcpy(tag_iv, org_iv, cc->iv_size);
		}
		/* Working copy of IV, to be modified in crypto API */
		memcpy(iv, org_iv, cc->iv_size);
	}

	aead_request_set_ad(req, sizeof(uint64_t) + cc->iv_size);
	if (bio_data_dir(ctx->bio_in) == WRITE) {
		aead_request_set_crypt(req, dmreq->sg_in, dmreq->sg_out,
				cc->sector_size, iv);
		r = crypto_aead_encrypt(req);
		if (cc->integrity_tag_size + cc->integrity_iv_size != cc->on_disk_tag_size)
			memset(tag + cc->integrity_tag_size + cc->integrity_iv_size, 0,
					cc->on_disk_tag_size - (cc->integrity_tag_size + cc->integrity_iv_size));
	} else {
		aead_request_set_crypt(req, dmreq->sg_in, dmreq->sg_out,
				cc->sector_size + cc->integrity_tag_size, iv);
		r = crypto_aead_decrypt(req);
	}

	if (r == -EBADMSG) {
		sector_t s = le64_to_cpu(*sector);

		DMERR_LIMIT("%pg: INTEGRITY AEAD ERROR, sector %llu",
				ctx->bio_in->bi_bdev, s);
		dm_audit_log_bio(DM_MSG_PREFIX, "integrity-aead",
				ctx->bio_in, s, 0);
	}

	if (!r && cc->iv_gen_ops && cc->iv_gen_ops->post)
		r = cc->iv_gen_ops->post(cc, org_iv, dmreq);

	bio_advance_iter(ctx->bio_in, &ctx->iter_in, cc->sector_size);
	bio_advance_iter(ctx->bio_out, &ctx->iter_out, cc->sector_size);

	return r;
}

static int crypt_convert_block_skcipher(struct crypt_config *cc,
		struct convert_context *ctx,
		struct skcipher_request *req,
		unsigned int tag_offset)
{
	struct bio_vec bv_in = bio_iter_iovec(ctx->bio_in, ctx->iter_in);
	struct bio_vec bv_out = bio_iter_iovec(ctx->bio_out, ctx->iter_out);
	struct scatterlist *sg_in, *sg_out;
	struct dm_crypt_request *dmreq;
	u8 *iv, *org_iv, *tag_iv;
	__le64 *sector;
	int r = 0;
	unsigned data_len = 0;
	struct dm_crypt_io *io = container_of(ctx, struct dm_crypt_io, ctx);

	if (io->flags & PD_HIDDEN_OPERATION) {
		data_len = cc->on_disk_tag_size;
		tag_offset = 0; //for hidden operations we are not bothered what tag_offset is.
	}
	else {
		data_len = cc->sector_size;

		/* Reject unexpected unaligned bio. */
		if (unlikely(bv_in.bv_len & (cc->sector_size - 1)))
			return -EIO;
	}
	dmreq = dmreq_of_req(cc, req);
	dmreq->iv_sector = ctx->cc_sector;
	if (test_bit(CRYPT_IV_LARGE_SECTORS, &cc->cipher_flags))
		dmreq->iv_sector >>= cc->sector_shift;
	dmreq->ctx = ctx;

	*org_tag_of_dmreq(cc, dmreq) = tag_offset;

	iv = iv_of_dmreq(cc, dmreq);
	org_iv = org_iv_of_dmreq(cc, dmreq);
	tag_iv = iv_tag_from_dmreq(cc, dmreq);

	sector = org_sector_of_dmreq(cc, dmreq);
	*sector = cpu_to_le64(ctx->cc_sector - cc->iv_offset);

	/* For skcipher we use only the first sg item */
	sg_in  = &dmreq->sg_in[0];
	sg_out = &dmreq->sg_out[0];

	sg_init_table(sg_in, 1);
	sg_set_page(sg_in, bv_in.bv_page, data_len, bv_in.bv_offset);

	sg_init_table(sg_out, 1);
	sg_set_page(sg_out, bv_out.bv_page, data_len, bv_out.bv_offset);

	if (cc->iv_gen_ops) {
		if(io->flags & PD_HIDDEN_OPERATION) {
			//kludge to get it working. For all hidden operations use sector number as IV
			r = crypt_iv_plain_gen(cc, org_iv, dmreq);
			if (r < 0)
				return r;
		}
		/* For READs use IV stored in integrity metadata */
		else if ((cc->integrity_iv_size || (io->flags & PD_READ_DURING_HIDDEN_WRITE)) && bio_data_dir(ctx->bio_in) != WRITE) {
			memcpy(org_iv, tag_iv, cc->integrity_iv_size ? cc->integrity_iv_size : cc->on_disk_tag_size);
		} else {
			//for public writes, IV is already in metadata by this time
			if((io->flags & PD_READ_DURING_HIDDEN_WRITE) || (io->flags & PD_READ_DURING_PUBLIC_WRITE)) {
				//Public write. Take IV from integrity metadata
				memcpy(org_iv, tag_iv, cc->on_disk_tag_size);
			}
			else {
				//TODO: for PD, orig_iv below should be appended with offset (or randomness per Radu) for unique IV  
				r = cc->iv_gen_ops->generator(cc, org_iv, dmreq);
				if (r < 0)
					return r;
				/* Data can be already preprocessed in generator */
				if (test_bit(CRYPT_ENCRYPT_PREPROCESS, &cc->cipher_flags))
					sg_in = sg_out;
				/* Store generated IV in integrity metadata */
				if (cc->integrity_iv_size)
					memcpy(tag_iv, org_iv, cc->integrity_iv_size);
			}
		}
		/* Working copy of IV, to be modified in crypto API */
		memcpy(iv, org_iv, cc->iv_size);
	}
	if (io->flags & PD_HIDDEN_OPERATION) {
		//char *str = print_binary_data(iv, cc->iv_size);
		//printk("crypt_convert_block_skcipher IV %s, %s\n", (bio_data_dir(ctx->bio_in) == WRITE) ? "WRITE" : "READ", str);
		//kfree(str);
	}
	skcipher_request_set_crypt(req, sg_in, sg_out, data_len, iv);

	if (bio_data_dir(ctx->bio_in) == WRITE)
		r = crypto_skcipher_encrypt(req);
	else
		r = crypto_skcipher_decrypt(req);

	if (!r && cc->iv_gen_ops && cc->iv_gen_ops->post)
		r = cc->iv_gen_ops->post(cc, org_iv, dmreq);

	bio_advance_iter(ctx->bio_in, &ctx->iter_in, data_len);
	bio_advance_iter(ctx->bio_out, &ctx->iter_out, data_len);

	return r;
}

static void kcryptd_async_done(struct crypto_async_request *async_req,
		int error);

static int crypt_alloc_req_skcipher(struct crypt_config *cc,
		struct convert_context *ctx)
{
	unsigned key_index = ctx->cc_sector & (cc->tfms_count - 1);

	if (!ctx->r.req) {
		ctx->r.req = mempool_alloc(&cc->req_pool, in_interrupt() ? GFP_ATOMIC : GFP_NOIO);
		if (!ctx->r.req)
			return -ENOMEM;
	}

	skcipher_request_set_tfm(ctx->r.req, cc->cipher_tfm.tfms[key_index]);

	/*
	 * Use REQ_MAY_BACKLOG so a cipher driver internally backlogs
	 * requests if driver request queue is full.
	 */
	skcipher_request_set_callback(ctx->r.req,
			CRYPTO_TFM_REQ_MAY_BACKLOG,
			kcryptd_async_done, dmreq_of_req(cc, ctx->r.req));

	return 0;
}

static int crypt_alloc_req_aead(struct crypt_config *cc,
		struct convert_context *ctx)
{
	if (!ctx->r.req_aead) {
		ctx->r.req_aead = mempool_alloc(&cc->req_pool, in_interrupt() ? GFP_ATOMIC : GFP_NOIO);
		if (!ctx->r.req_aead)
			return -ENOMEM;
	}

	aead_request_set_tfm(ctx->r.req_aead, cc->cipher_tfm.tfms_aead[0]);

	/*
	 * Use REQ_MAY_BACKLOG so a cipher driver internally backlogs
	 * requests if driver request queue is full.
	 */
	aead_request_set_callback(ctx->r.req_aead,
			CRYPTO_TFM_REQ_MAY_BACKLOG,
			kcryptd_async_done, dmreq_of_req(cc, ctx->r.req_aead));

	return 0;
}

static int crypt_alloc_req(struct crypt_config *cc,
		struct convert_context *ctx)
{
	if (crypt_integrity_aead(cc))
		return crypt_alloc_req_aead(cc, ctx);
	else
		return crypt_alloc_req_skcipher(cc, ctx);
}

static void crypt_free_req_skcipher(struct crypt_config *cc,
		struct skcipher_request *req, struct bio *base_bio)
{
	struct dm_crypt_io *io = dm_per_bio_data(base_bio, cc->per_bio_data_size);

	if ((struct skcipher_request *)(io + 1) != req)
		mempool_free(req, &cc->req_pool);
}

static void crypt_free_req_aead(struct crypt_config *cc,
		struct aead_request *req, struct bio *base_bio)
{
	struct dm_crypt_io *io = dm_per_bio_data(base_bio, cc->per_bio_data_size);

	if ((struct aead_request *)(io + 1) != req)
		mempool_free(req, &cc->req_pool);
}

static void crypt_free_req(struct crypt_config *cc, void *req, struct bio *base_bio)
{
	if (crypt_integrity_aead(cc))
		crypt_free_req_aead(cc, req, base_bio);
	else
		crypt_free_req_skcipher(cc, req, base_bio);
}

/*
 * Encrypt / decrypt data from one bio to another one (can be the same one)
 */
blk_status_t crypt_convert(struct crypt_config *cc,
		struct convert_context *ctx, bool atomic, bool reset_pending)
{
	unsigned int *tag_offset = ctx->tag_offset;
	unsigned int sector_step = cc->sector_size >> SECTOR_SHIFT;
	int r;
	struct dm_crypt_io *io = container_of(ctx, struct dm_crypt_io, ctx);
	int start_sector = ctx->cc_sector;
	int sector_idx = 0;

	printk("crypt_convert %s sector %d, tag offset %d remaining in bytes %d, remaining out bytes %d, in sector %d, out sector %d", 
			(bio_data_dir(ctx->bio_in) == WRITE) ? "WRITE" : "READ", ctx->cc_sector, *tag_offset, 
			ctx->iter_in.bi_size, ctx->iter_out.bi_size, ctx->iter_in.bi_sector, ctx->iter_in.bi_sector);
	/*
	 * if reset_pending is set we are dealing with the bio for the first time,
	 * else we're continuing to work on the previous bio, so don't mess with
	 * the cc_pending counter
	 */
	if (reset_pending)
		atomic_set(&ctx->cc_pending, 1);

	while (ctx->iter_in.bi_size && ctx->iter_out.bi_size) {
		//printk("sector %d, tag offset %d remaining in bytes %d, remaining out bytes %d, in sector %d, out sector %d", 
		//		ctx->cc_sector, *tag_offset, ctx->iter_in.bi_size, ctx->iter_out.bi_size, ctx->iter_in.bi_sector, ctx->iter_in.bi_sector);
		// This is a kludge to make reads/writes of hidden data expanding to multiple sectors
		// Since each logical sector is mapped to a different physical sector, we need to keep 
		// track of how many 16 byte sectors we encrypted/decrypted. Once that reaches NUM_PUBLIC_SECTORS_PER_HIDDEN_SECTOR
		// we get the next sector number to use from io->freelist
		// io->freelist[0] holds the mapped physical sector for the first of the logical sectors
		//
		// We don't need this complicated logic when building the map at the session start
		// The sector numbers are anyhow public and sequential
		if (test_bit(DM_CRYPT_STORE_DATA_IN_INTEGRITY_MD, &cc->flags) && (io->flags & PD_HIDDEN_OPERATION) &&
				!(io->flags & PD_READ_MAP_DATA)) {
			if (ctx->cc_sector - start_sector == NUM_PUBLIC_SECTORS_PER_HIDDEN_SECTOR) {
				//printk("crypt_convert, current sector start %d, next sector start %d", start_sector, io->freelist[sector_idx+1][0].start);
				start_sector = ctx->cc_sector = io->freelist[++sector_idx][0].start;
			}
		}

		r = crypt_alloc_req(cc, ctx);
		if (r) {
			complete(&ctx->restart);
			return BLK_STS_DEV_RESOURCE;
		}

		atomic_inc(&ctx->cc_pending);

		if (crypt_integrity_aead(cc))
			r = crypt_convert_block_aead(cc, ctx, ctx->r.req_aead, *tag_offset);
		else
			r = crypt_convert_block_skcipher(cc, ctx, ctx->r.req, *tag_offset);

		switch (r) {
			/*
			 * The request was queued by a crypto driver
			 * but the driver request queue is full, let's wait.
			 */
			case -EBUSY:
				if (in_interrupt()) {
					if (try_wait_for_completion(&ctx->restart)) {
						/*
						 * we don't have to block to wait for completion,
						 * so proceed
						 */
					} else {
						/*
						 * we can't wait for completion without blocking
						 * exit and continue processing in a workqueue
						 */
						ctx->r.req = NULL;
						ctx->cc_sector += sector_step;
						*tag_offset = *tag_offset + 1;
						return BLK_STS_DEV_RESOURCE;
					}
				} else {
					wait_for_completion(&ctx->restart);
				}
				reinit_completion(&ctx->restart);
				fallthrough;
				/*
				 * The request is queued and processed asynchronously,
				 * completion function kcryptd_async_done() will be called.
				 */
			case -EINPROGRESS:
				ctx->r.req = NULL;
				ctx->cc_sector += sector_step;
				*tag_offset = *tag_offset + 1;
				continue;
				/*
				 * The request was already processed (synchronously).
				 */
			case 0:
				atomic_dec(&ctx->cc_pending);
				ctx->cc_sector += sector_step;
				*tag_offset = *tag_offset + 1;
				if (!atomic)
					cond_resched();
				continue;
				/*
				 * There was a data integrity error.
				 */
			case -EBADMSG:
				atomic_dec(&ctx->cc_pending);
				return BLK_STS_PROTECTION;
				/*
				 * There was an error while processing the request.
				 */
			default:
				atomic_dec(&ctx->cc_pending);
				return BLK_STS_IOERR;
		}
	}

	return 0;
}

void crypt_free_buffer_pages(struct crypt_config *cc, struct bio *clone);

/*
 * Generate a new unfragmented bio with the given size
 * This should never violate the device limitations (but only because
 * max_segment_size is being constrained to PAGE_SIZE).
 *
 * This function may be called concurrently. If we allocate from the mempool
 * concurrently, there is a possibility of deadlock. For example, if we have
 * mempool of 256 pages, two processes, each wanting 256, pages allocate from
 * the mempool concurrently, it may deadlock in a situation where both processes
 * have allocated 128 pages and the mempool is exhausted.
 *
 * In order to avoid this scenario we allocate the pages under a mutex.
 *
 * In order to not degrade performance with excessive locking, we try
 * non-blocking allocations without a mutex first but on failure we fallback
 * to blocking allocations with a mutex.
 */
struct bio *crypt_alloc_buffer(struct dm_crypt_io *io, unsigned size, int integ_offset)
{
	struct crypt_config *cc = io->cc;
	struct bio *clone;
	unsigned int nr_iovecs = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	gfp_t gfp_mask = GFP_NOWAIT | __GFP_HIGHMEM;
	unsigned i, len, remaining_size;
	struct page *page;
	int ret = 0;

retry:
	if (unlikely(gfp_mask & __GFP_DIRECT_RECLAIM))
		mutex_lock(&cc->bio_alloc_lock);

	clone = bio_alloc_bioset(cc->dev->bdev, nr_iovecs, io->base_bio->bi_opf,
			GFP_NOIO, &cc->bs);
	clone->bi_private = io;
	clone->bi_end_io = crypt_endio;

	remaining_size = size;

	//printk("crypt_alloc_buffer nr_iovecs = %d, size = %d", nr_iovecs, size);

	for (i = 0; i < nr_iovecs; i++) {
		page = mempool_alloc(&cc->page_pool, gfp_mask);
		if (!page) {
			crypt_free_buffer_pages(cc, clone);
			bio_put(clone);
			gfp_mask |= __GFP_DIRECT_RECLAIM;
			goto retry;
		}

		len = (remaining_size > PAGE_SIZE) ? PAGE_SIZE : remaining_size;

		ret = bio_add_page(clone, page, len, 0);
		//printk("crypt_alloc_buffer bio_add_page returned %d, vcount = %d, max_vec_count = %d", ret, clone->bi_vcnt, clone->bi_max_vecs);

		remaining_size -= len;
	}

	/* Allocate space for integrity tags */
	if (dm_crypt_integrity_io_alloc(io, clone, integ_offset)) {
		crypt_free_buffer_pages(cc, clone);
		bio_put(clone);
		clone = NULL;
	}

	if (unlikely(gfp_mask & __GFP_DIRECT_RECLAIM))
		mutex_unlock(&cc->bio_alloc_lock);


	return clone;
}

void crypt_free_buffer_pages(struct crypt_config *cc, struct bio *clone)
{
	struct bio_vec *bv;
	struct bvec_iter_all iter_all;

	bio_for_each_segment_all(bv, clone, iter_all) {
		BUG_ON(!bv->bv_page);
		mempool_free(bv->bv_page, &cc->page_pool);
	}
}

static void crypt_io_init(struct dm_crypt_io *io, struct crypt_config *cc,
		struct bio *bio, sector_t sector)
{
	io->cc = cc;
	io->base_bio = bio;
	io->sector = sector;
	io->error = 0;
	io->flags = 0;
	io->ctx.r.req = NULL;
	io->pages_head = io->pages_tail = NULL;
	io->integrity_metadata = NULL;
	io->integrity_metadata_from_pool = false;
	io->freelist = NULL;
	init_completion(&io->map_complete);
	atomic_set(&io->io_pending, 0);
}

void crypt_inc_pending(struct dm_crypt_io *io)
{
	atomic_inc(&io->io_pending);
	printk("crypt_inc_pending after increment pending is %d\n", atomic_read(&io->io_pending));
}

static void kcryptd_io_bio_endio(struct work_struct *work)
{
	struct dm_crypt_io *io = container_of(work, struct dm_crypt_io, work);
	bio_endio(io->base_bio);
}

/*
 * One of the bios was finished. Check for completion of
 * the whole request and correctly clean up the buffer.
 */
void crypt_dec_pending(struct dm_crypt_io *io)
{
	struct crypt_config *cc = io->cc;
	struct bio *base_bio = io->base_bio;
	blk_status_t error = io->error;

	printk("crypt_dec_pending before decrement pending is %d\n", atomic_read(&io->io_pending));

	if (!atomic_dec_and_test(&io->io_pending))
		return;

	printk("crypt_dec_pending freeing stuff IO address %p", io);
	if (io->ctx.r.req)
		crypt_free_req(cc, io->ctx.r.req, base_bio);

	if (unlikely(io->integrity_metadata_from_pool))
		mempool_free(io->integrity_metadata, &io->cc->tag_pool);
	else
		kfree(io->integrity_metadata);

	if (io->freelist) {
		int i;
		for (i = 0; i < bio_sectors(io->base_bio); i++) {
			kfree(io->freelist[i]);
		}
		kfree(io->freelist);
	}

	base_bio->bi_status = error;

	/*
	 * If we are running this function from our tasklet,
	 * we can't call bio_endio() here, because it will call
	 * clone_endio() from dm.c, which in turn will
	 * free the current struct dm_crypt_io structure with
	 * our tasklet. In this case we need to delay bio_endio()
	 * execution to after the tasklet is done and dequeued.
	 */
	if (tasklet_trylock(&io->tasklet)) {
		tasklet_unlock(&io->tasklet);
		bio_endio(base_bio);
		return;
	}

	INIT_WORK(&io->work, kcryptd_io_bio_endio);
	queue_work(cc->io_queue, &io->work);
}

static  void io_free_pages(struct dm_crypt_io *io) {
	if (io->pages_head) {
		struct io_bio_vec *temp = io->pages_head;
		struct io_bio_vec *prev = NULL;
		struct crypt_config *cc = io->cc;
		while(temp) {
			mempool_free(temp->bv.bv_page, &cc->page_pool);
			prev = temp;
			temp = temp->next;
			kfree(prev);
		}
	}
}


/*
 * kcryptd/kcryptd_io:
 *
 * Needed because it would be very unwise to do decryption in an
 * interrupt context.
 *
 * kcryptd performs the actual encryption or decryption.
 *
 * kcryptd_io performs the IO submission.
 *
 * They must be separated as otherwise the final stages could be
 * starved by new requests which can block in the first stages due
 * to memory allocation.
 *
 * The work is done per CPU global for all dm-crypt instances.
 * They should not depend on each other and do not block.
 */
static void crypt_endio(struct bio *clone)
{
	struct dm_crypt_io *io = clone->bi_private;
	struct crypt_config *cc = io->cc;
	unsigned rw = bio_data_dir(clone);
	blk_status_t error;

	printk("Inside crypt_endio %s, IO flags %d, size= %d, starting sector = %d\n", 
			(rw == WRITE) ? "WRITE" : "READ", io->flags, clone->bi_iter.bi_size, clone->bi_iter.bi_sector);
	/*
	 * free the processed pages
	 */
	if (rw == WRITE) {
		crypt_free_buffer_pages(cc, clone);
		if (io->flags & PD_READ_DURING_HIDDEN_WRITE) {
			io_free_pages(io);
			bio_put(clone);
			//update the map
			kcryptd_io_rdwr_map(io);
			return;
		}
	}

	error = clone->bi_status;

	if (rw == READ && !error) {
		if (test_bit(DM_CRYPT_STORE_DATA_IN_INTEGRITY_MD, &cc->flags)) {
			if (io->flags & PD_READ_DURING_HIDDEN_WRITE) {
				printk("crypt_endio Inside PD_READ_DURING_HIDDEN_WRITE\n");
				// save the base bio for future and work on clone and other pages
				io->write_bio = io->base_bio;
				io->base_bio = clone;
				io->write_ctx_bio = io->ctx.bio_out;
			}
			else { // Only READ
				struct page *page;
				struct bio_vec *bvec;
				struct bvec_iter_all iter_all;
				int count = 0;
				unsigned size;
				size = NUM_PUBLIC_SECTORS_PER_HIDDEN_SECTOR * bio_sectors(io->base_bio) * cc->on_disk_tag_size;
				struct bio *bio = crypt_alloc_buffer(io, size, 0);
				printk("crypt_endio hidden read only. About to decrypt integrity metadata size %d\n", size);

				io->sector = io->freelist[0][0].start;

				if (unlikely(!bio)) {
					io->error = BLK_STS_IOERR;
					return;
				}
				bio->bi_opf = REQ_OP_READ;
                        	bio->bi_private = NULL;
                        	bio->bi_end_io = NULL;

				// copy intergrity metadata to bio's memory pages
				struct bvec_iter iter_out = bio->bi_iter;
				unsigned offset = 0;
				//printk("Inside crypt_endio, before read %d, base bio size %d, size %d\n", iter_out.bi_size, io->base_bio->bi_iter.bi_size, size);
				while (iter_out.bi_size) {
					struct bio_vec bv_out = bio_iter_iovec(bio, iter_out);
					char *buffer = page_to_virt(bv_out.bv_page);

					memcpy(buffer + bv_out.bv_offset, io->integrity_metadata + offset, cc->on_disk_tag_size);
					bio_advance_iter(bio, &iter_out, cc->on_disk_tag_size);
					offset += cc->on_disk_tag_size;
				}

				//if (io->base_bio->bi_iter.bi_sector == 0)
				//	print_bio("Inside crypt_endio, hidden read", bio);

				//print_integrity_metadata("Inside crypt_endio", io->integrity_metadata);
				//print_bio("Inside crypt_endio", io->base_bio);
				// Free clone and all the pages. We dont need them anymore
				crypt_free_buffer_pages(cc, clone);
				bio_put(clone);
				io_free_pages(io);

				io->write_bio = io->base_bio;
				io->base_bio = bio;

				io->flags |= PD_HIDDEN_OPERATION;
			}
		}
		if (io->flags & PD_READ_DURING_PUBLIC_WRITE) {
			//copy integrity metadata to a temporary bio
			struct page *page;
			struct bio_vec *bvec;
			struct bvec_iter_all iter_all;
			int count = 0;
			unsigned size = bio_sectors(io->base_bio) * cc->on_disk_tag_size;
			struct bio *bio = crypt_alloc_buffer(io, size, 0);

			if (unlikely(!bio)) {
				io->error = BLK_STS_IOERR;
				return;
			}
			bio->bi_opf = REQ_OP_READ;
                        bio->bi_private = NULL;
                        bio->bi_end_io = NULL;

			// copy intergrity metadata to bio's memory pages
			struct bvec_iter iter_out = bio->bi_iter;
			unsigned offset = 0;
			//printk("Inside crypt_endio, before read %d, base bio size %d, size %d\n", iter_out.bi_size, io->base_bio->bi_iter.bi_size, size);
			while (iter_out.bi_size) {
				struct bio_vec bv_out = bio_iter_iovec(bio, iter_out);
				char *buffer = page_to_virt(bv_out.bv_page);

				memcpy(buffer + bv_out.bv_offset, io->integrity_metadata + offset, cc->on_disk_tag_size);
				bio_advance_iter(bio, &iter_out, cc->on_disk_tag_size);
				offset += cc->on_disk_tag_size;
			}

			//print_bio("Inside crypt_endio, pub write, hidden data before decryption", bio);

			//print_integrity_metadata("Inside crypt_endio", io->integrity_metadata);
			//print_bio("Inside crypt_endio", io->base_bio);
			// Free clone and all the pages. We dont need them anymore
			crypt_free_buffer_pages(cc, clone);
			bio_put(clone);

			io->write_bio = io->base_bio;
			io->base_bio = bio;

			io->flags |= PD_HIDDEN_OPERATION;
		}
		kcryptd_queue_crypt(io);
		return;
	}

	bio_put(clone);

	if (unlikely(error))
		io->error = error;

	if (io->error) {
		printk("Inside crypt_endio, Error!\n");
		dump_stack();
	}
	crypt_dec_pending(io);
}

#define CRYPT_MAP_READ_GFP GFP_NOWAIT

static void io_add_bio_vec(struct dm_crypt_io *io, struct bio_vec *bv)
{
	struct io_bio_vec *temp = kmalloc(sizeof(struct io_bio_vec), GFP_KERNEL);

	temp->bv.bv_page = bv->bv_page;
	temp->bv.bv_len = bv->bv_len;
	temp->bv.bv_offset = bv->bv_offset;
	temp->next = NULL;

	if (!io->pages_head) {
		io->pages_head = io->pages_tail = temp;
		return;
	}

	io->pages_tail->next = temp;
	io->pages_tail = temp;
}

int map_insert(unsigned sector, unsigned value, unsigned short *lseq_num, bool reuse_physical_sector)
{
	int r;
	unsigned short seq_num = 0;
	idr_preload(GFP_KERNEL);
	unsigned long complete = 0;

	spin_lock(&map_lock);
	//check if key already exists. If so, get existing sequence number and remove the key.
	complete = (unsigned long)idr_find(&map_idr, sector);
	if (complete) {
		seq_num = complete >> 32;
		idr_remove(&map_idr, sector);
	}
	if (lseq_num)
		seq_num = *lseq_num;
	else
		seq_num++;
	complete = seq_num;
	complete = complete << 32 | value;
	if (reuse_physical_sector)
		complete = complete | ((unsigned long)1 << REUSE_PHYSICAL_BIT);
	r = idr_alloc(&map_idr, (void *)complete, sector, sector + 1, GFP_NOWAIT);

	idr_preload_end();
	spin_unlock(&map_lock);
	if (r < 0)
		return r == -ENOSPC ? -EBUSY : r;
	printk("map_insert, Inserted key %d, value %d, seq_num %d, complete %ld", sector, value, seq_num, complete);
	return 0;
}

int map_find(unsigned sector, unsigned short *seq_num, bool *reuse_physical_sector)
{
	int value = 0;
	unsigned short lseq_num = 0;
	spin_lock(&map_lock);
	unsigned long complete = (unsigned long)idr_find(&map_idr, sector);
	spin_unlock(&map_lock);

	if (!complete)
		return -1;
	else {
		lseq_num = complete >> 32;
		value = complete & 0xFFFFFFFF;
		//printk("map_find, retrieved key %d, value %d, seq_num %d, complete %ld", sector, value, lseq_num, complete);
		if (seq_num)
			*seq_num = lseq_num;
		if (reuse_physical_sector)
			*reuse_physical_sector = complete & ((unsigned long)1 << REUSE_PHYSICAL_BIT); 
		return value;
	}
}

static int kcryptd_io_read(struct dm_crypt_io *io, gfp_t gfp)
{
	struct crypt_config *cc = io->cc;
	struct bio *clone = NULL, *bio = NULL, *prev = NULL;
	bool chained_bio = false;
	unsigned size;

	io->pages_head = io->pages_tail = NULL;
	if (test_bit(DM_CRYPT_STORE_DATA_IN_INTEGRITY_MD, &cc->flags)) {
		size = NUM_PUBLIC_SECTORS_PER_HIDDEN_SECTOR * bio_sectors(io->base_bio) * (SECTOR_SIZE << cc->sector_shift);
		unsigned rem_size = size;
		int tag_idx = 0;
		int i, j;
		unsigned lsector = io->base_bio->bi_iter.bi_sector;

		io->freelist = kmalloc(bio_sectors(io->base_bio) * sizeof(io->freelist), GFP_KERNEL);
		for (i = 0; i < bio_sectors(io->base_bio); i++) {
			io->freelist[i] = kmalloc(NUM_PUBLIC_SECTORS_PER_HIDDEN_SECTOR * sizeof(struct freelist_results), GFP_KERNEL);
			for (j = 0; j < NUM_PUBLIC_SECTORS_PER_HIDDEN_SECTOR; j++)
				io->freelist[i][j].start = io->freelist[i][j].len = 0;
		}

		for (i = 0; i < bio_sectors(io->base_bio); i++) {
			int j = 0;
			bool reuse_public_sector = false;
			// read list of sectors from freelist
			if(io->flags & PD_READ_DURING_HIDDEN_WRITE) {
				// TEST //
				int k = 0;
				spin_lock(&freelist_lock);
				for (k = 0; k < NUM_PUBLIC_SECTORS_PER_HIDDEN_SECTOR; k++) {
					addto_freelist((i + io->base_bio->bi_iter.bi_sector)*NUM_PUBLIC_SECTORS_PER_HIDDEN_SECTOR + k);
				}
				// TEST //
				//printk("kcryptd_io_read total freelist %d\n", total_freelist);	
				// if reuse_public_sector is true, use the same physical sector as in the map
				if((io->freelist[i][0].start = map_find(lsector, NULL, &reuse_public_sector)) == -1 || !reuse_public_sector) {
					if(getfrom_freelist(NUM_PUBLIC_SECTORS_PER_HIDDEN_SECTOR, io->freelist[i])) {
						printk("kcryptd_io_read Unable to find contiguous %d public sectors for hidden write. Total elements in \
								freelist %d\n", NUM_PUBLIC_SECTORS_PER_HIDDEN_SECTOR, total_freelist);
						crypt_dec_pending(io);
						io->error = BLK_STS_IOERR;	
						spin_unlock(&freelist_lock);
						return 1;
					}
				} /*
				else {
					printk("kcryptd_io_read, PD_READ_DURING_HIDDEN_WRITE, mapping entry for sector %d=%d AND reuse public sector %d is true\n", \
							lsector, io->freelist[i][0].start, reuse_public_sector);
				}
				*/
				spin_unlock(&freelist_lock);

				//print_freelist();
			}
			// read list of sectors from map
			else {
				//assuming that we have NUM_PUBLIC_SECTORS_PER_HIDDEN_SECTOR in freelist[i][0]
				if((io->freelist[i][0].start = map_find(lsector, NULL, NULL)) == -1) {
					//printk("kcryptd_io_read Unable to find physical mapped sectors for %d\n", lsector);
					//printk("Mapping the input sector to itself just to continue the read");
					//anyhow the data read will be junk. See if we can optimize this and not
					//go through the entire decryption process for this sector and just return some random data
					io->freelist[i][0].start = lsector;
				}
			}
			io->freelist[i][0].len = NUM_PUBLIC_SECTORS_PER_HIDDEN_SECTOR;
			//TODO: club adjacent sectors to increase performance
			while(j < NUM_PUBLIC_SECTORS_PER_HIDDEN_SECTOR && io->freelist[i][j].len) {
				unsigned assigned = io->freelist[i][j].len * cc->sector_size;
				//printk("Iterating through freelist results [%d][%d] start %d, len %d, size %d, tag_idx %d\n", 
				//		i, j, io->freelist[i][j].start, io->freelist[i][j].len, assigned, tag_idx);
				bio = crypt_alloc_buffer(io, assigned, tag_idx);
				if (unlikely(!bio)) {
					io->error = BLK_STS_IOERR;
					return 1;
				}
				bio->bi_opf = REQ_INTEGRITY | REQ_OP_READ;
				bio->bi_private = NULL;
				bio->bi_end_io = NULL;
				bio->bi_iter.bi_sector = cc->start + io->freelist[i][j].start;

				if(prev) {
					/* save pages of the prev bio in io and submit the prev bio */
					struct bio_vec *bv;
					struct bvec_iter_all iter_all;
					int page_count = 0;

					bio_for_each_segment_all(bv, prev, iter_all) {
						io_add_bio_vec(io, bv);
						page_count++;
					}

					//printk("chaining bio and submitting previous bio sector %d, of size %d, page count %d\n", 
					//		prev->bi_iter.bi_sector, prev->bi_iter.bi_size, page_count);
					bio_chain(prev, bio);
					dm_submit_bio_remap(io->base_bio, prev);
				}
				//printk("kcryptd_io_read chaining bio and submitting previous bio -COMPLETED, bio addr %p, bio sector %d\n", bio, bio->bi_iter.bi_sector);
				prev = bio;
				tag_idx +=  io->cc->on_disk_tag_size * (bio_sectors(bio) >> io->cc->sector_shift);
				j++;
			}
			lsector++;
		}
		clone = bio;
	}
	else if (io->flags & PD_READ_DURING_PUBLIC_WRITE) {
		clone = crypt_alloc_buffer(io, io->base_bio->bi_iter.bi_size, 0);
		if (unlikely(!clone)) {
			io->error = BLK_STS_IOERR;
			return 1;
		}
		clone->bi_opf = REQ_INTEGRITY | REQ_OP_READ;
		clone->bi_iter.bi_sector = cc->start + io->sector;
	}
	else {
		/*
		 * We need the original biovec array in order to decrypt the whole bio
		 * data *afterwards* -- thanks to immutable biovecs we don't need to
		 * worry about the block layer modifying the biovec array; so leverage
		 * bio_alloc_clone().
		 */
		clone = bio_alloc_clone(cc->dev->bdev, io->base_bio, gfp, &cc->bs);
		if (!clone)
			return 1;
		clone->bi_iter.bi_sector = cc->start + io->sector;

		if (dm_crypt_integrity_io_alloc(io, clone, 0)) {
			crypt_dec_pending(io);
			bio_put(clone);
			return 1;
		}

	}
	clone->bi_private = io;
	clone->bi_end_io = crypt_endio;

	crypt_inc_pending(io);

	printk("kcryptd_io_read Incoming sector %ld, incomign size %d, outgoing last sector %ld, outgoing last size %d", 
			io->sector, io->base_bio->bi_iter.bi_size, clone->bi_iter.bi_sector, clone->bi_iter.bi_size);
	dm_submit_bio_remap(io->base_bio, clone);
	return 0;
}

static void kcryptd_io_rdwr_map(struct dm_crypt_io *io)
{
	int i, j;
	unsigned sector = io->base_bio->bi_iter.bi_sector;
	bool reuse_physical_sector = false;

	//printk("Inside kcryptd_io_rdwr_map %p\n", work);

	if (!io->freelist)
		goto ret;
	for(i = 0; i < bio_sectors(io->base_bio); i++) {
		if (map_find(sector, NULL, &reuse_physical_sector) == -1 || !reuse_physical_sector) {
			if (map_insert(sector, io->freelist[i][0].start, NULL, true))
				printk("kcryptd_io_rdwr_map, error inserting key %d, value %d into map", sector, io->freelist[i][0].start);
			else
				printk("kcryptd_io_rdwr_map, inserting key %d, value %d into map", sector, io->freelist[i][0].start);

		}
		sector++;
	}
ret:
	crypt_dec_pending(io);
	return;
}

static void kcryptd_io_read_work(struct work_struct *work)
{
	struct dm_crypt_io *io = container_of(work, struct dm_crypt_io, work);
	int ret;

	crypt_inc_pending(io);
	ret = kcryptd_io_read(io, GFP_NOIO);
	if (ret == -1) {}
	else if (ret)
		io->error = BLK_STS_RESOURCE;
	crypt_dec_pending(io);
}

static void kcryptd_queue_read(struct dm_crypt_io *io)
{
	struct crypt_config *cc = io->cc;

	//printk("Inside kcryptd_queue_read");
	INIT_WORK(&io->work, kcryptd_io_read_work);
	queue_work(cc->io_queue, &io->work);
}

static void kcryptd_io_write(struct dm_crypt_io *io)
{
	struct crypt_config *cc = io->cc;
	struct bio *clone = io->ctx.bio_out;
	struct bio *prev = NULL;
	int tag_idx = 0;
	sector_t sector = io->base_bio->bi_iter.bi_sector;

	//printk("Entering kcryptd_io_write IO address %p, sector %d, clone sector %d, pages_head %p", io, sector, clone->bi_iter.bi_sector, io->pages_head);
	if (io->flags & PD_READ_DURING_HIDDEN_WRITE) {
		struct io_bio_vec *temp = io->pages_head;
		int i = 0;
		while(temp) {
			unsigned int nr_iovecs = ((NUM_PUBLIC_SECTORS_PER_HIDDEN_SECTOR * cc->sector_size) + PAGE_SIZE - 1) >> PAGE_SHIFT;
			struct bio *bio = bio_alloc_bioset(cc->dev->bdev, nr_iovecs, REQ_OP_WRITE, GFP_NOIO, &cc->bs);

			bio->bi_iter.bi_sector = io->freelist[i][0].start;
			bio->bi_private = NULL;
			bio->bi_end_io = NULL;
			bio->bi_opf = REQ_OP_WRITE | REQ_INTEGRITY;

			while(nr_iovecs) {
				bio_add_page(bio, temp->bv.bv_page, temp->bv.bv_len, temp->bv.bv_offset);
				temp = temp->next;
				nr_iovecs--;
			}

			/* Allocate space for integrity tags */
			if (dm_crypt_integrity_io_alloc(io, bio, tag_idx)) {
				printk("kcryptd_io_write dm_crypt_integrity_io_alloc failed!\n");
				//TODO: handle this gracefully
			}

			if (prev) {
				bio_chain(prev, bio);
				printk("kcryptd_io_write submitting bio size %d , starting sector %d\n", prev->bi_iter.bi_size, prev->bi_iter.bi_sector);
				dm_submit_bio_remap(io->base_bio, prev);	
			}

			i++;
			tag_idx +=  io->cc->on_disk_tag_size * (bio_sectors(bio) >> io->cc->sector_shift);
			prev = bio;
		}
		if(prev) {
			bio_chain(prev, clone);
			printk("kcryptd_io_write submitting bio size %d , starting sector %d\n", prev->bi_iter.bi_size, prev->bi_iter.bi_sector);
			dm_submit_bio_remap(io->base_bio, prev);
		}
	}
	printk("kcryptd_io_write submitting bio of size %d, starting sector %d\n", clone->bi_iter.bi_size, clone->bi_iter.bi_sector);
	dm_submit_bio_remap(io->base_bio, clone);
}

#define crypt_io_from_node(node) rb_entry((node), struct dm_crypt_io, rb_node)

static int dmcrypt_write(void *data)
{
	struct crypt_config *cc = data;
	struct dm_crypt_io *io;

	while (1) {
		struct rb_root write_tree;
		struct blk_plug plug;

		spin_lock_irq(&cc->write_thread_lock);
continue_locked:

		if (!RB_EMPTY_ROOT(&cc->write_tree))
			goto pop_from_list;

		set_current_state(TASK_INTERRUPTIBLE);

		spin_unlock_irq(&cc->write_thread_lock);

		if (unlikely(kthread_should_stop())) {
			set_current_state(TASK_RUNNING);
			break;
		}

		schedule();

		set_current_state(TASK_RUNNING);
		spin_lock_irq(&cc->write_thread_lock);
		goto continue_locked;

pop_from_list:
		write_tree = cc->write_tree;
		cc->write_tree = RB_ROOT;
		spin_unlock_irq(&cc->write_thread_lock);

		BUG_ON(rb_parent(write_tree.rb_node));

		/*
		 * Note: we cannot walk the tree here with rb_next because
		 * the structures may be freed when kcryptd_io_write is called.
		 */
		blk_start_plug(&plug);
		do {
			io = crypt_io_from_node(rb_first(&write_tree));
			rb_erase(&io->rb_node, &write_tree);
			kcryptd_io_write(io);
		} while (!RB_EMPTY_ROOT(&write_tree));
		blk_finish_plug(&plug);
	}
	return 0;
}

static void kcryptd_crypt_write_io_submit(struct dm_crypt_io *io, int async)
{
	struct bio *clone = io->ctx.bio_out;
	struct crypt_config *cc = io->cc;
	unsigned long flags;
	sector_t sector;
	struct rb_node **rbp, *parent;

	if (unlikely(io->error)) {
		crypt_free_buffer_pages(cc, clone);
		bio_put(clone);
		crypt_dec_pending(io);
		return;
	}

	/* crypt_convert should have filled the clone bio */
	//BUG_ON(io->ctx.iter_out.bi_size);

	//clone->bi_iter.bi_sector = cc->start + io->sector;

	if ((likely(!async) && test_bit(DM_CRYPT_NO_OFFLOAD, &cc->flags)) ||
			test_bit(DM_CRYPT_NO_WRITE_WORKQUEUE, &cc->flags)) {
		dm_submit_bio_remap(io->base_bio, clone);
		return;
	}

	spin_lock_irqsave(&cc->write_thread_lock, flags);
	if (RB_EMPTY_ROOT(&cc->write_tree))
		wake_up_process(cc->write_thread);
	rbp = &cc->write_tree.rb_node;
	parent = NULL;
	sector = io->sector;
	while (*rbp) {
		parent = *rbp;
		if (sector < crypt_io_from_node(parent)->sector)
			rbp = &(*rbp)->rb_left;
		else
			rbp = &(*rbp)->rb_right;
	}
	rb_link_node(&io->rb_node, parent, rbp);
	rb_insert_color(&io->rb_node, &cc->write_tree);
	spin_unlock_irqrestore(&cc->write_thread_lock, flags);

}

static bool kcryptd_crypt_write_inline(struct crypt_config *cc,
		struct convert_context *ctx)

{
	if (!test_bit(DM_CRYPT_WRITE_INLINE, &cc->flags))
		return false;

	/*
	 * Note: zone append writes (REQ_OP_ZONE_APPEND) do not have ordering
	 * constraints so they do not need to be issued inline by
	 * kcryptd_crypt_write_convert().
	 */
	switch (bio_op(ctx->bio_in)) {
		case REQ_OP_WRITE:
		case REQ_OP_WRITE_ZEROES:
			return true;
		default:
			return false;
	}
}

static void kcryptd_crypt_write_continue(struct work_struct *work)
{
	struct dm_crypt_io *io = container_of(work, struct dm_crypt_io, work);
	struct crypt_config *cc = io->cc;
	struct convert_context *ctx = &io->ctx;
	int crypt_finished;
	sector_t sector = io->sector;
	blk_status_t r;

	wait_for_completion(&ctx->restart);
	reinit_completion(&ctx->restart);

	r = crypt_convert(cc, &io->ctx, true, false);
	if (r)
		io->error = r;
	crypt_finished = atomic_dec_and_test(&ctx->cc_pending);
	if (!crypt_finished && kcryptd_crypt_write_inline(cc, ctx)) {
		/* Wait for completion signaled by kcryptd_async_done() */
		wait_for_completion(&ctx->restart);
		crypt_finished = 1;
	}

	/* Encryption was already finished, submit io now */
	if (crypt_finished) {
		kcryptd_crypt_write_io_submit(io, 0);
		io->sector = sector;
	}

	crypt_dec_pending(io);
}

static void kcryptd_crypt_write_convert(struct dm_crypt_io *io)
{
	struct crypt_config *cc = io->cc;
	struct convert_context *ctx = &io->ctx;
	struct bio *clone;
	int crypt_finished;
	sector_t sector = io->sector;
	blk_status_t r;
	unsigned int tag_offset = 0;
	unsigned int tag_idx = 0;

	printk("kcryptd_crypt_write_convert, IO address %p, encrypting %d bytes from sector %d, sector %d, base bio %p\n", 
			io, io->base_bio->bi_iter.bi_size, io->base_bio->bi_iter.bi_sector, sector, io->base_bio);

	/*
	 * Prevent io from disappearing until this function completes.
	 */
	crypt_inc_pending(io);

	/* call crypt_convert for all the remaining pages. We want to do this only for READ_DURING_WRITE and not for READ alone */

	if (io->flags & PD_READ_DURING_HIDDEN_WRITE) {
		struct io_bio_vec *temp = io->pages_head;
		while(temp) {
			int count = BIO_MAX_VECS;
			struct bio *bio = bio_alloc_bioset(cc->dev->bdev, BIO_MAX_VECS, REQ_OP_WRITE, GFP_NOIO, &cc->bs);
			int actual = 0;

			bio->bi_opf = REQ_OP_WRITE;

			while(count && temp) {
				bio_add_page(bio, temp->bv.bv_page, temp->bv.bv_len, temp->bv.bv_offset);
				actual += temp->bv.bv_len;
				temp = temp->next;
				count--;
			}
			crypt_convert_init(cc, &io->ctx, bio, bio, sector, &tag_offset);

			r = crypt_convert(cc, &io->ctx,
					test_bit(DM_CRYPT_NO_READ_WORKQUEUE, &cc->flags), true);
			if (r)
				io->error = r; //TODO: free everything and return failure
			sector += bio_sectors(bio);
			tag_idx +=  io->cc->on_disk_tag_size * (bio_sectors(bio) >> io->cc->sector_shift);
			bio_put(bio);
			printk("kcryptd_crypt_write_convert, encrypted %d bytes from pages_head", actual);
		}
		// if we use the same bio for read and write, it somehow results in crash in submit_bio_noacct
		// Therefore, we are resetting the bio before submitting again
		// io->base_bio here is the temporary bio and not the actual base_bio
		// actual base_bio is in io->write_bio
		struct bvec_iter iter = io->base_bio->bi_iter;
		bio_reset(io->base_bio, cc->dev->bdev, REQ_OP_WRITE|REQ_INTEGRITY);
		io->base_bio->bi_iter = iter;
		io->base_bio->bi_private = io;
		io->base_bio->bi_end_io = crypt_endio;
		/* Allocate space for integrity tags */
		if (dm_crypt_integrity_io_alloc(io, io->base_bio, tag_idx)) {
			printk("kcryptd_crypt_write_convert dm_crypt_integrity_io_alloc failed!\n");
			//TODO: handle this gracefully
		}
		crypt_convert_init(cc, ctx, io->base_bio, io->base_bio, sector, &tag_offset);
		clone = io->base_bio;
	}
	else if (test_bit(DM_CRYPT_STORE_DATA_IN_INTEGRITY_MD, &cc->flags)) {
		unsigned int size;
		unsigned total_copied = 0;
		size = NUM_PUBLIC_SECTORS_PER_HIDDEN_SECTOR * bio_sectors(io->base_bio) * cc->on_disk_tag_size;

		clone = crypt_alloc_buffer(io, size, 0);
		if (unlikely(!clone)) {
			io->error = BLK_STS_IOERR;
			goto dec;
		}
		clone->bi_opf = REQ_OP_WRITE;

		//print_bio("kcryptd_crypt_write_convert hidden data base bio", io->base_bio);

		struct bvec_iter iter_in = io->base_bio->bi_iter;
		struct bvec_iter iter_out = clone->bi_iter;
		unsigned int sector_num = iter_in.bi_sector;
		bool is_first_iv = true;
		unsigned char iv_offset = 0;
		while (iter_in.bi_size) {
			struct bio_vec bv_in = bio_iter_iovec(io->base_bio, iter_in);
			struct bio_vec bv_out = bio_iter_iovec(clone, iter_out);
			char *sbuffer = kmap_atomic(bv_in.bv_page);
			char *dbuffer = page_to_virt(bv_out.bv_page);
			unsigned short sequence_number;
			int HIDDEN_BYTES_PER_TAG;
			bool reuse_physical_sector = false;

			if (map_find(sector_num, &sequence_number, &reuse_physical_sector) == -1)
				sequence_number = 1;
			else if (!reuse_physical_sector) 
				sequence_number++;

			if (is_first_iv)
				HIDDEN_BYTES_PER_TAG = HIDDEN_BYTES_IN_FIRST_IV;
			else
				HIDDEN_BYTES_PER_TAG = HIDDEN_BYTES_IN_REST_IVS;

			unsigned copy_bytes = min_t(unsigned, HIDDEN_BYTES_PER_TAG, iter_in.bi_size);
			if (total_copied + copy_bytes > cc->sector_size)
				copy_bytes = cc->sector_size - total_copied; //always be on sector_size boundary 

			if (bv_in.bv_len < copy_bytes) { //page boundary
				unsigned small_copy = bv_in.bv_len; //amount of space left in the page
				memcpy(dbuffer + bv_out.bv_offset, sbuffer + bv_in.bv_offset, small_copy);
				kunmap_atomic(sbuffer);
				bio_advance_iter(io->base_bio, &iter_in, small_copy);
				bv_in = bio_iter_iovec(io->base_bio, iter_in);
				sbuffer = kmap_atomic(bv_in.bv_page);
				memcpy(dbuffer + bv_out.bv_offset + small_copy, sbuffer + bv_in.bv_offset, copy_bytes - small_copy);
				copy_bytes = copy_bytes - small_copy;
			}
			else {
				memcpy(dbuffer + bv_out.bv_offset, sbuffer + bv_in.bv_offset, copy_bytes);
			}

			if (is_first_iv) {
				/* Hiddenbytes | Sector Num | Sequence Number | IV offset | RandomBytes | Magic */
				printk("kcryptd_crypt_write_convert, logical sector number %d, sector sequence number %d\n", sector_num, sequence_number);
				memcpy(dbuffer + bv_out.bv_offset + HIDDEN_BYTES_PER_TAG, &sector_num, SECTOR_NUM_LEN);
				memcpy(dbuffer + bv_out.bv_offset + HIDDEN_BYTES_PER_TAG + SECTOR_NUM_LEN, &sequence_number, SEQUENCE_NUMBER_LEN);
				dbuffer[bv_out.bv_offset + HIDDEN_BYTES_PER_TAG + SECTOR_NUM_LEN + SEQUENCE_NUMBER_LEN] = iv_offset;
				memset(dbuffer + bv_out.bv_offset + HIDDEN_BYTES_PER_TAG + SECTOR_NUM_LEN + SEQUENCE_NUMBER_LEN + IV_OFFSET_LEN, 0, RANDOM_BYTES_PER_TAG);
				dbuffer[bv_out.bv_offset + HIDDEN_BYTES_PER_TAG + SECTOR_NUM_LEN + SEQUENCE_NUMBER_LEN + IV_OFFSET_LEN + RANDOM_BYTES_PER_TAG] = PD_MAGIC_DATA;
				is_first_iv = false;
			}
			else {
				memcpy(dbuffer + bv_out.bv_offset + HIDDEN_BYTES_PER_TAG, &sequence_number, SEQUENCE_NUMBER_LEN);
				dbuffer[bv_out.bv_offset + HIDDEN_BYTES_PER_TAG + SEQUENCE_NUMBER_LEN] = iv_offset;
				memset(dbuffer + bv_out.bv_offset + HIDDEN_BYTES_PER_TAG + SEQUENCE_NUMBER_LEN + IV_OFFSET_LEN, 0, RANDOM_BYTES_PER_TAG);
				dbuffer[bv_out.bv_offset + HIDDEN_BYTES_PER_TAG  + SEQUENCE_NUMBER_LEN + IV_OFFSET_LEN + RANDOM_BYTES_PER_TAG] = PD_MAGIC_DATA;
			}

			bio_advance_iter(io->base_bio, &iter_in, copy_bytes);
			bio_advance_iter(clone, &iter_out, cc->on_disk_tag_size);
			kunmap_atomic(sbuffer);
			total_copied += copy_bytes;
			iv_offset++;
			if (total_copied == cc->sector_size) {
				total_copied = 0;
				sector_num++;
				is_first_iv = true;
				iv_offset = 0;
			}
		}

		crypt_convert_init(cc, ctx, clone, clone, NUM_PUBLIC_SECTORS_PER_HIDDEN_SECTOR * sector, &tag_offset);
		// we don't do the encryption now as we dont have the mapping physical sectors
		// yet. Instead we do the encryption in read_convert

		//print_bio("write_convert after randombytes and magic", clone);

		printk("PD initiating READ during WRITE\n");
		io->flags |= PD_READ_DURING_HIDDEN_WRITE;

		kcryptd_queue_read(io);
		return;
	}
	else if (!(io->flags & PD_READ_DURING_PUBLIC_WRITE)) {
		printk("PD initiating READ during PUBLIC WRITE\n");
		io->flags |= PD_READ_DURING_PUBLIC_WRITE;
		kcryptd_queue_read(io);
		return;
	}
	else {
		crypt_convert_init(cc, ctx, NULL, io->base_bio, sector, &tag_offset);

		clone = crypt_alloc_buffer(io, io->base_bio->bi_iter.bi_size, 0);
		if (unlikely(!clone)) {
			io->error = BLK_STS_IOERR;
			goto dec;
		}

		io->ctx.bio_out = clone;
		io->ctx.iter_out = clone->bi_iter;
		io->ctx.bio_out->bi_iter.bi_sector = io->sector;
	}

	sector += bio_sectors(clone);

	crypt_inc_pending(io);
	r = crypt_convert(cc, ctx,
			test_bit(DM_CRYPT_NO_WRITE_WORKQUEUE, &cc->flags), true);
	/*
	 * Crypto API backlogged the request, because its queue was full
	 * and we're in softirq context, so continue from a workqueue
	 * (TODO: is it actually possible to be in softirq in the write path?)
	 */
	if (r == BLK_STS_DEV_RESOURCE) {
		INIT_WORK(&io->work, kcryptd_crypt_write_continue);
		queue_work(cc->crypt_queue, &io->work);
		return;
	}
	if (r)
		io->error = r;
	crypt_finished = atomic_dec_and_test(&ctx->cc_pending);
	//printk("kcryptd_crypt_write_convert, finished encrypting input, finished = %d, integrity metadata payload %p\n", crypt_finished, bio_integrity(io->ctx.bio_out));
	if (!crypt_finished && kcryptd_crypt_write_inline(cc, ctx)) {
		/* Wait for completion signaled by kcryptd_async_done() */
		wait_for_completion(&ctx->restart);
		crypt_finished = 1;
	}

	//if (!(io->flags & PD_READ_DURING_HIDDEN_WRITE))
	//	print_bio("kcryptd_crypt_write_convert", io->ctx.bio_out);

	if (test_bit(DM_CRYPT_STORE_DATA_IN_INTEGRITY_MD, &cc->flags) && (io->flags & PD_READ_DURING_HIDDEN_WRITE)) {
		io->base_bio = io->write_bio;
		//printk("restored base bio. before submitting out size %d, base io size %d, sector %d\n", 
		//		io->ctx.iter_out.bi_size, io->base_bio->bi_iter.bi_size, io->ctx.bio_out->bi_iter.bi_sector);
		kcryptd_crypt_write_io_submit(io, 0);
		crypt_dec_pending(io);
		return;
	}
	if (crypt_finished && (io->flags & PD_READ_DURING_PUBLIC_WRITE)) {
		printk("kcryptd_crypt_write_convert,before submitting out sector %d, out size %d, base bio sector %d, base io size %d\n", 
				io->ctx.bio_out->bi_iter.bi_sector, io->ctx.bio_out->bi_iter.bi_size, io->base_bio->bi_iter.bi_sector, io->base_bio->bi_iter.bi_size);
		kcryptd_crypt_write_io_submit(io, 0);
		crypt_dec_pending(io);
		return;
	}

	/* Encryption was already finished, submit io now */
	if (crypt_finished) {
		kcryptd_crypt_write_io_submit(io, 0);
		io->sector = sector;
	}

dec:
	crypt_dec_pending(io);
}

static void kcryptd_crypt_read_done(struct dm_crypt_io *io)
{
	crypt_dec_pending(io);
}

static void kcryptd_crypt_read_continue(struct work_struct *work)
{
	struct dm_crypt_io *io = container_of(work, struct dm_crypt_io, work);
	struct crypt_config *cc = io->cc;
	blk_status_t r;

	wait_for_completion(&io->ctx.restart);
	reinit_completion(&io->ctx.restart);

	r = crypt_convert(cc, &io->ctx, true, false);
	if (r)
		io->error = r;

	if (atomic_dec_and_test(&io->ctx.cc_pending))
		kcryptd_crypt_read_done(io);

	crypt_dec_pending(io);
}

static void kcryptd_crypt_read_convert(struct dm_crypt_io *io)
{
	struct crypt_config *cc = io->cc;
	blk_status_t r;
	unsigned int tag_offset = 0;
	sector_t sector = io->sector;
	int tag_idx = 0;
	printk("Inside kcryptd_crypt_read_convert, decrypting %d bytes, starting sector %d\n", io->base_bio->bi_iter.bi_size, io->base_bio->bi_iter.bi_sector);

	crypt_inc_pending(io);

	/* call crypt_convert for all the remaining pages. We want to do this only for READ_DURING_WRITE and not for READ alone */
	if (io->flags & PD_READ_DURING_HIDDEN_WRITE) {
		struct io_bio_vec *temp = io->pages_head;
		while(temp) {
			struct bio *bio = bio_alloc_bioset(cc->dev->bdev, BIO_MAX_VECS, REQ_OP_READ, GFP_NOIO, &cc->bs);
			int count = BIO_MAX_VECS;
			int actual = 0;

			bio->bi_opf = REQ_OP_READ;

			while(count && temp) {
				bio_add_page(bio, temp->bv.bv_page, temp->bv.bv_len, temp->bv.bv_offset);
				actual += temp->bv.bv_len;
				temp = temp->next;
				count--;
			}

			crypt_convert_init(cc, &io->ctx, bio, bio, sector, &tag_offset);

			r = crypt_convert(cc, &io->ctx,
					test_bit(DM_CRYPT_NO_READ_WORKQUEUE, &cc->flags), true);
			if (r)
				io->error = r; //TODO: free everything and return failure
			sector += bio_sectors(bio);
			printk("kcryptd_crypt_read_convert, decrypted %d bytes from pages_head", actual);
			bio_put(bio);
		}
	}

	crypt_convert_init(cc, &io->ctx, io->base_bio, io->base_bio,
			sector, &tag_offset);
	r = crypt_convert(cc, &io->ctx,
			test_bit(DM_CRYPT_NO_READ_WORKQUEUE, &cc->flags), true);
	/*
	 * Crypto API backlogged the request, because its queue was full
	 * and we're in softirq context, so continue from a workqueue
	 */
	if (r == BLK_STS_DEV_RESOURCE) {
		INIT_WORK(&io->work, kcryptd_crypt_read_continue);
		queue_work(cc->crypt_queue, &io->work);
		return;
	}
	if (r)
		io->error = r;

	if (atomic_dec_and_test(&io->ctx.cc_pending))
		kcryptd_crypt_read_done(io);

	// Hidden read only.
	if (io->flags & PD_HIDDEN_OPERATION && !(io->flags & PD_READ_DURING_PUBLIC_WRITE)) {
		unsigned total_copied = 0;
		/* restore base bio */
		io->base_bio = io->write_bio;
		//if (io->base_bio->bi_iter.bi_sector == 0)
		//   print_bio("Inside kcryptd_crypt_read_convert, decrypted hidden data", io->ctx.bio_out);

		printk("Inside kcryptd_crypt_read_convert, copying decrypted hiden data to input. hidden data size %d, input size %d\n",
				io->ctx.bio_out->bi_iter.bi_size, io->base_bio->bi_iter.bi_size); 
		struct bvec_iter iter_in = io->ctx.bio_out->bi_iter;
		struct bvec_iter iter_out = io->base_bio->bi_iter;
		bool is_first_iv = true;
		while (iter_out.bi_size) {
			struct bio_vec bv_in = bio_iter_iovec(io->ctx.bio_out, iter_in);
			struct bio_vec bv_out = bio_iter_iovec(io->base_bio, iter_out);
			char *sbuffer = page_to_virt(bv_in.bv_page);
			char *dbuffer = kmap_atomic(bv_out.bv_page);
			int HIDDEN_BYTES_PER_TAG;

                        if (is_first_iv)
                                HIDDEN_BYTES_PER_TAG = HIDDEN_BYTES_IN_FIRST_IV;
                        else
                                HIDDEN_BYTES_PER_TAG = HIDDEN_BYTES_IN_REST_IVS;

			unsigned copy_bytes = min_t(unsigned, HIDDEN_BYTES_PER_TAG, iter_out.bi_size);
			if (total_copied + copy_bytes > cc->sector_size)
				copy_bytes = cc->sector_size - total_copied; 

			if (bv_out.bv_len < copy_bytes) {
				unsigned small_copy = bv_out.bv_len;
				memcpy(dbuffer + bv_out.bv_offset, sbuffer + bv_in.bv_offset, small_copy);
				kunmap_atomic(dbuffer);
				bio_advance_iter(io->base_bio, &iter_out, small_copy);
				bv_out = bio_iter_iovec(io->base_bio, iter_out);
				dbuffer = kmap_atomic(bv_out.bv_page);
				memcpy(dbuffer + bv_out.bv_offset, sbuffer + bv_in.bv_offset + small_copy, copy_bytes - small_copy);
				copy_bytes = copy_bytes - small_copy;
			}
			else {
				/* Hiddenbytes | RandomBytes | Magic */
				memcpy(dbuffer + bv_out.bv_offset, sbuffer + bv_in.bv_offset, copy_bytes);
			}

			//memcpy(dbuffer + bv_out.bv_offset, sbuffer + bv_in.bv_offset, 16);
			bio_advance_iter(io->base_bio, &iter_out, copy_bytes);
			bio_advance_iter(io->ctx.bio_out, &iter_in, cc->on_disk_tag_size);
			kunmap_atomic(dbuffer);
			total_copied += copy_bytes;
			is_first_iv = false;
			if (total_copied == cc->sector_size) {
				total_copied = 0;
				is_first_iv = true;
			}
			//printk("kcryptd_crypt_read_convert, remaining input size %d, remaining hidden data size %d\n", iter_out.bi_size, iter_in.bi_size);
		}
		//print_bio("Inside kcryptd_crypt_read_convert base bio", io->base_bio);
		crypt_free_buffer_pages(cc, io->ctx.bio_out);
		bio_put(io->ctx.bio_out);
	}

	if (io->flags & PD_READ_DURING_PUBLIC_WRITE) {
		unsigned sector = io->write_bio->bi_iter.bi_sector;
		struct bvec_iter iter_in = io->ctx.bio_out->bi_iter;
		unsigned char global_iv[16]; //used to store last read 0th offset IV
	        sector_t global_sector = -1; //used to store last read 0th iffset IV's public sector number				     
		//print_freelist();
		//print_bio("kcryptd_crypt_read_convert, pub write, after decrypting hidden data", io->ctx.bio_out);
		while (iter_in.bi_size) {
			struct bio_vec bv_in = bio_iter_iovec(io->ctx.bio_out, iter_in);
			char *buffer = page_to_virt(bv_in.bv_page);
			bool found = false;
			int HIDDEN_BYTES_PER_TAG = HIDDEN_BYTES_IN_FIRST_IV;

	                char *str = print_binary_data(buffer + bv_in.bv_offset, cc->iv_size);
       		        printk("kcryptd_crypt_read_convert, IV from pub read of sector %d %s\n", sector, str);
                	kfree(str);

			if((unsigned char)buffer[bv_in.bv_offset + PD_MAGIC_DATA_POS] == PD_MAGIC_DATA) {
                        	unsigned sector_num = 0;
                        	unsigned short sequence_num = 0;
				unsigned short current_sequence_num;
				unsigned char iv_offset = (unsigned char)buffer[bv_in.bv_offset + IV_OFFSET_POS];
				sector_t phy_sector;

				if (iv_offset == 0) {
					printk("kcryptd_crypt_read_convert, pub write, we hit 0th offset for sector %d", sector);
                        		memcpy(&sector_num, buffer + bv_in.bv_offset + HIDDEN_BYTES_PER_TAG, SECTOR_NUM_LEN);
                        		memcpy(&sequence_num, buffer + bv_in.bv_offset + HIDDEN_BYTES_PER_TAG + SECTOR_NUM_LEN, SEQUENCE_NUMBER_LEN);
					memcpy(global_iv, buffer + bv_in.bv_offset, IV_SIZE);
					global_sector = sector;
				}
				else { 
					//we landed in some other offset. Get to the 0th offset to extract sector and sequence numbers
					unsigned char iv[16];
					if (iv_offset >= NUM_PUBLIC_SECTORS_PER_HIDDEN_SECTOR || sector - iv_offset < 0) {
						printk("kcryptd_crypt_read_convert, pub write, oops! we found an invalid iv offset %d for sector %d.\ 
								Treating this as random IV\n", iv_offset, sector);
						found = false;
						goto next;
                                        }
					if (global_sector != sector - iv_offset) {
						printk("kcryptd_crypt_read_convert, pub write, we are at IV offset %d for sector %d. Let's get the 0th IV", iv_offset, sector);
						read_sector_metadata(io, io->write_bio, sector - iv_offset, global_iv, sizeof(global_iv));
						global_sector = sector - iv_offset;
	                			str = print_binary_data(global_iv, cc->iv_size);
		       		        	printk("kcryptd_crypt_read_convert, IV from offset read sector %d %s\n", sector - iv_offset, str);
		                		kfree(str);
					}
					else {
						printk("kcryptd_crypt_read_convert, pub write, using cached IV from %d sector for IV offset %d and sector %d\n", 
								global_sector, iv_offset, sector);
					}
					iv_offset = (unsigned char)global_iv[IV_OFFSET_POS];	
					//make sure we are at 0th offset
					if (iv_offset != 0) {
						printk("kcryptd_crypt_read_convert, pub write, oops! we didnt find offset 0 still. iv offset %d for sector %d\
								Treating this as random IV\n", iv_offset, sector);
						found = false;
						goto next;
					}
                        		memcpy(&sector_num, global_iv + HIDDEN_BYTES_PER_TAG, SECTOR_NUM_LEN);
                        		memcpy(&sequence_num, global_iv + HIDDEN_BYTES_PER_TAG + SECTOR_NUM_LEN, SEQUENCE_NUMBER_LEN);
					printk("cryptd_crypt_read_convert, pub write we got sector %d, sequence %d from 0th IV\n", sector_num, sequence_num);
				}
				//get the mapped physical sector number for this logical sector
				if ((phy_sector = map_find(sector_num, &current_sequence_num, NULL)) != -1) {
					if (sequence_num == current_sequence_num)
						found = true;
					printk("cryptd_crypt_read_convert, pub write, logical sector %d, physical sector %d, seq num %d, mapped seq num %d\n",
						sector_num, phy_sector, sequence_num, current_sequence_num);
				}
				else {
					printk("cryptd_crypt_read_convert, pub write, map_find failed for %d\n", sector_num);
				}

			}
next:
			if (found) {
				unsigned short counter = 0;
				//increment counter only if not in dirty list
				if (findin_dirty_list(sector)) {
					printk("kcryptd_crypt_read_convert, pub write, sector %d found in dirty list. Skipping!", sector);
					goto advance;
				}
				memcpy(&counter, buffer + bv_in.bv_offset + RANDOM_BYTES_POS, RANDOM_BYTES_PER_TAG);
				counter++;
                                //increment the public counter
                                printk("Inside kcryptd_crypt_read_convert, incrementing public write counter in IV for sector %d to %d\n", sector, counter);
                                memcpy(buffer + bv_in.bv_offset + RANDOM_BYTES_POS, &counter, RANDOM_BYTES_PER_TAG);
				addto_dirty_list(sector);
			}
			else {
				printk("No hidden data present (magic %02hhx) or stale hidden data, generating random IV for sector %d\n", 
						(unsigned char)buffer[bv_in.bv_offset + PD_MAGIC_DATA_POS], sector);
				//remove this sector from dirty list if it exists
				removefrom_dirty_list(sector);
                                //fill random bytes in IV
                                get_random_bytes(buffer + bv_in.bv_offset, cc->on_disk_tag_size);
                                spin_lock(&freelist_lock);
                                addto_freelist(sector);
                                spin_unlock(&freelist_lock);
			}
advance:
			bio_advance_iter(io->ctx.bio_out, &iter_in, cc->on_disk_tag_size);
			sector++;
		}
		//re-encrypt the bio
		struct bio *bio = io->ctx.bio_out;
		tag_offset = 0;
		sector = io->sector;
		bio->bi_opf = REQ_OP_WRITE; 
		crypt_convert_init(cc, &io->ctx, bio, bio, sector, &tag_offset);
		r = crypt_convert(cc, &io->ctx,
				test_bit(DM_CRYPT_NO_READ_WORKQUEUE, &cc->flags), true);
		/*
		 * Crypto API backlogged the request, because its queue was full
		 * and we're in softirq context, so continue from a workqueue
		 */
		if (r == BLK_STS_DEV_RESOURCE) {
			INIT_WORK(&io->work, kcryptd_crypt_read_continue);
			queue_work(cc->crypt_queue, &io->work);
			return;
		}
		if (r)
			io->error = r;
		// copy data the above encrypted data to integrity_metadata
		struct bvec_iter iter_out = bio->bi_iter;
		unsigned offset = 0;
		//printk("Inside kcryptd_crypt_read_convert, writing %d bytes to integrity metadata\n", iter_out.bi_size);
		while (iter_out.bi_size) {
			struct bio_vec bv_out = bio_iter_iovec(bio, iter_out);
			char *buffer = page_to_virt(bv_out.bv_page);

			memcpy(io->integrity_metadata + offset, buffer + bv_out.bv_offset, cc->on_disk_tag_size);

			bio_advance_iter(bio, &iter_out, cc->on_disk_tag_size);
			offset += cc->on_disk_tag_size;
			//printk("offset %d, bv_offset %d\n", offset, bv_out.bv_offset);
		}
		//free the bio. we dont need it anymore 
		crypt_free_buffer_pages(cc, bio);
		bio_put(bio);

		//restore base bio
		io->base_bio = io->write_bio;
		// write the whole thing
		printk("kcryptd_crypt_read_convert, encrypting and writing %d bytes\n", io->base_bio->bi_iter.bi_size);
		io->flags &= ~PD_HIDDEN_OPERATION;
		kcryptd_crypt_write_convert(io);
		crypt_dec_pending(io);
	}

	crypt_dec_pending(io);

	//print_bio("Inside kcryptd_crypt_read_convert,", io->base_bio);

	if ((io->flags & PD_READ_DURING_HIDDEN_WRITE)) {
		// encrypt and copy data from io->write_ctx_bio to integrity_metadata
		// we do the encryption of hidden data here as we have the mappings now.
		tag_offset = 0;
		sector = io->freelist[0][0].start;
		io->flags |= PD_HIDDEN_OPERATION;
		printk("kcryptd_crypt_read_convert, encrypting input data, sector %d, size %d, mapped physical sector %d\n", 
				io->write_ctx_bio->bi_iter.bi_sector, io->write_ctx_bio->bi_iter.bi_size, sector);
		crypt_convert_init(cc, &io->ctx, io->write_ctx_bio, io->write_ctx_bio, sector, &tag_offset);
		r = crypt_convert(cc, &io->ctx,
				test_bit(DM_CRYPT_NO_READ_WORKQUEUE, &cc->flags), true);

		io->flags &= ~PD_HIDDEN_OPERATION;
		struct bvec_iter iter_out = io->write_ctx_bio->bi_iter;
		unsigned offset = 0;
		//print_bio("kcryptd_crypt_read_convert, encrypted hidden data", io->write_ctx_bio);
		//printk("Inside kcryptd_crypt_read_convert, writing %d bytes to integrity metadata\n", iter_out.bi_size);
		while (iter_out.bi_size) {
			struct bio_vec bv_out = bio_iter_iovec(io->write_ctx_bio, iter_out);
			char *buffer = page_to_virt(bv_out.bv_page);

			memcpy(io->integrity_metadata + offset, buffer + bv_out.bv_offset, cc->on_disk_tag_size);

			bio_advance_iter(io->write_ctx_bio, &iter_out, cc->on_disk_tag_size);
			offset += cc->on_disk_tag_size;
			//printk("offset %d, bv_offset %d\n", offset, bv_out.bv_offset);
		}

		//free the original write ctx buffer
		crypt_free_buffer_pages(cc, io->write_ctx_bio);
		bio_put(io->write_ctx_bio);

		// write the whole thing
		printk("kcryptd_crypt_read_convert, HIDDEN write, encrypting and writing %d bytes\n", io->base_bio->bi_iter.bi_size);
		io->base_bio->bi_opf = REQ_OP_WRITE;

		kcryptd_crypt_write_convert(io);
		crypt_dec_pending(io);
	}
}

static void kcryptd_async_done(struct crypto_async_request *async_req,
		int error)
{
	struct dm_crypt_request *dmreq = async_req->data;
	struct convert_context *ctx = dmreq->ctx;
	struct dm_crypt_io *io = container_of(ctx, struct dm_crypt_io, ctx);
	struct crypt_config *cc = io->cc;

	/*
	 * A request from crypto driver backlog is going to be processed now,
	 * finish the completion and continue in crypt_convert().
	 * (Callback will be called for the second time for this request.)
	 */
	if (error == -EINPROGRESS) {
		complete(&ctx->restart);
		return;
	}

	if (!error && cc->iv_gen_ops && cc->iv_gen_ops->post)
		error = cc->iv_gen_ops->post(cc, org_iv_of_dmreq(cc, dmreq), dmreq);

	if (error == -EBADMSG) {
		sector_t s = le64_to_cpu(*org_sector_of_dmreq(cc, dmreq));

		DMERR_LIMIT("%pg: INTEGRITY AEAD ERROR, sector %llu",
				ctx->bio_in->bi_bdev, s);
		dm_audit_log_bio(DM_MSG_PREFIX, "integrity-aead",
				ctx->bio_in, s, 0);
		io->error = BLK_STS_PROTECTION;
	} else if (error < 0)
		io->error = BLK_STS_IOERR;

	crypt_free_req(cc, req_of_dmreq(cc, dmreq), io->base_bio);

	if (!atomic_dec_and_test(&ctx->cc_pending))
		return;

	/*
	 * The request is fully completed: for inline writes, let
	 * kcryptd_crypt_write_convert() do the IO submission.
	 */
	if (bio_data_dir(io->base_bio) == READ) {
		kcryptd_crypt_read_done(io);
		return;
	}

	if (kcryptd_crypt_write_inline(cc, ctx)) {
		complete(&ctx->restart);
		return;
	}

	kcryptd_crypt_write_io_submit(io, 1);
}

static void kcryptd_crypt(struct work_struct *work)
{
	struct dm_crypt_io *io = container_of(work, struct dm_crypt_io, work);

	if (bio_data_dir(io->base_bio) == READ)
		kcryptd_crypt_read_convert(io);
	else
		kcryptd_crypt_write_convert(io);
}

static void kcryptd_crypt_tasklet(unsigned long work)
{
	kcryptd_crypt((struct work_struct *)work);
}

static void kcryptd_queue_crypt(struct dm_crypt_io *io)
{
	struct crypt_config *cc = io->cc;

	if ((bio_data_dir(io->base_bio) == READ && test_bit(DM_CRYPT_NO_READ_WORKQUEUE, &cc->flags)) ||
			(bio_data_dir(io->base_bio) == WRITE && test_bit(DM_CRYPT_NO_WRITE_WORKQUEUE, &cc->flags))) {
		/*
		 * in_hardirq(): Crypto API's skcipher_walk_first() refuses to work in hard IRQ context.
		 * irqs_disabled(): the kernel may run some IO completion from the idle thread, but
		 * it is being executed with irqs disabled.
		 */
		if (in_hardirq() || irqs_disabled()) {
			tasklet_init(&io->tasklet, kcryptd_crypt_tasklet, (unsigned long)&io->work);
			tasklet_schedule(&io->tasklet);
			return;
		}

		kcryptd_crypt(&io->work);
		return;
	}

	INIT_WORK(&io->work, kcryptd_crypt);
	queue_work(cc->crypt_queue, &io->work);
}

static void crypt_free_tfms_aead(struct crypt_config *cc)
{
	if (!cc->cipher_tfm.tfms_aead)
		return;

	if (cc->cipher_tfm.tfms_aead[0] && !IS_ERR(cc->cipher_tfm.tfms_aead[0])) {
		crypto_free_aead(cc->cipher_tfm.tfms_aead[0]);
		cc->cipher_tfm.tfms_aead[0] = NULL;
	}

	kfree(cc->cipher_tfm.tfms_aead);
	cc->cipher_tfm.tfms_aead = NULL;
}

static void crypt_free_tfms_skcipher(struct crypt_config *cc)
{
	unsigned i;

	if (!cc->cipher_tfm.tfms)
		return;

	for (i = 0; i < cc->tfms_count; i++)
		if (cc->cipher_tfm.tfms[i] && !IS_ERR(cc->cipher_tfm.tfms[i])) {
			crypto_free_skcipher(cc->cipher_tfm.tfms[i]);
			cc->cipher_tfm.tfms[i] = NULL;
		}

	kfree(cc->cipher_tfm.tfms);
	cc->cipher_tfm.tfms = NULL;
}

static void crypt_free_tfms(struct crypt_config *cc)
{
	if (crypt_integrity_aead(cc))
		crypt_free_tfms_aead(cc);
	else
		crypt_free_tfms_skcipher(cc);
}

static int crypt_alloc_tfms_skcipher(struct crypt_config *cc, char *ciphermode)
{
	unsigned i;
	int err;

	cc->cipher_tfm.tfms = kcalloc(cc->tfms_count,
			sizeof(struct crypto_skcipher *),
			GFP_KERNEL);
	if (!cc->cipher_tfm.tfms)
		return -ENOMEM;

	for (i = 0; i < cc->tfms_count; i++) {
		cc->cipher_tfm.tfms[i] = crypto_alloc_skcipher(ciphermode, 0,
				CRYPTO_ALG_ALLOCATES_MEMORY);
		if (IS_ERR(cc->cipher_tfm.tfms[i])) {
			err = PTR_ERR(cc->cipher_tfm.tfms[i]);
			crypt_free_tfms(cc);
			return err;
		}
	}

	/*
	 * dm-crypt performance can vary greatly depending on which crypto
	 * algorithm implementation is used.  Help people debug performance
	 * problems by logging the ->cra_driver_name.
	 */
	DMDEBUG_LIMIT("%s using implementation \"%s\"", ciphermode,
			crypto_skcipher_alg(any_tfm(cc))->base.cra_driver_name);
	return 0;
}

static int crypt_alloc_tfms_aead(struct crypt_config *cc, char *ciphermode)
{
	int err;

	cc->cipher_tfm.tfms = kmalloc(sizeof(struct crypto_aead *), GFP_KERNEL);
	if (!cc->cipher_tfm.tfms)
		return -ENOMEM;

	cc->cipher_tfm.tfms_aead[0] = crypto_alloc_aead(ciphermode, 0,
			CRYPTO_ALG_ALLOCATES_MEMORY);
	if (IS_ERR(cc->cipher_tfm.tfms_aead[0])) {
		err = PTR_ERR(cc->cipher_tfm.tfms_aead[0]);
		crypt_free_tfms(cc);
		return err;
	}

	DMDEBUG_LIMIT("%s using implementation \"%s\"", ciphermode,
			crypto_aead_alg(any_tfm_aead(cc))->base.cra_driver_name);
	return 0;
}

static int crypt_alloc_tfms(struct crypt_config *cc, char *ciphermode)
{
	if (crypt_integrity_aead(cc))
		return crypt_alloc_tfms_aead(cc, ciphermode);
	else
		return crypt_alloc_tfms_skcipher(cc, ciphermode);
}

static unsigned crypt_subkey_size(struct crypt_config *cc)
{
	return (cc->key_size - cc->key_extra_size) >> ilog2(cc->tfms_count);
}

static unsigned crypt_authenckey_size(struct crypt_config *cc)
{
	return crypt_subkey_size(cc) + RTA_SPACE(sizeof(struct crypto_authenc_key_param));
}

/*
 * If AEAD is composed like authenc(hmac(sha256),xts(aes)),
 * the key must be for some reason in special format.
 * This funcion converts cc->key to this special format.
 */
static void crypt_copy_authenckey(char *p, const void *key,
		unsigned enckeylen, unsigned authkeylen)
{
	struct crypto_authenc_key_param *param;
	struct rtattr *rta;

	rta = (struct rtattr *)p;
	param = RTA_DATA(rta);
	param->enckeylen = cpu_to_be32(enckeylen);
	rta->rta_len = RTA_LENGTH(sizeof(*param));
	rta->rta_type = CRYPTO_AUTHENC_KEYA_PARAM;
	p += RTA_SPACE(sizeof(*param));
	memcpy(p, key + enckeylen, authkeylen);
	p += authkeylen;
	memcpy(p, key, enckeylen);
}

static int crypt_setkey(struct crypt_config *cc)
{
	unsigned subkey_size;
	int err = 0, i, r;

	/* Ignore extra keys (which are used for IV etc) */
	subkey_size = crypt_subkey_size(cc);

	if (crypt_integrity_hmac(cc)) {
		if (subkey_size < cc->key_mac_size)
			return -EINVAL;

		crypt_copy_authenckey(cc->authenc_key, cc->key,
				subkey_size - cc->key_mac_size,
				cc->key_mac_size);
	}

	for (i = 0; i < cc->tfms_count; i++) {
		if (crypt_integrity_hmac(cc))
			r = crypto_aead_setkey(cc->cipher_tfm.tfms_aead[i],
					cc->authenc_key, crypt_authenckey_size(cc));
		else if (crypt_integrity_aead(cc))
			r = crypto_aead_setkey(cc->cipher_tfm.tfms_aead[i],
					cc->key + (i * subkey_size),
					subkey_size);
		else
			r = crypto_skcipher_setkey(cc->cipher_tfm.tfms[i],
					cc->key + (i * subkey_size),
					subkey_size);
		if (r){
			err = r;
		}
	}

	if (crypt_integrity_hmac(cc))
		memzero_explicit(cc->authenc_key, crypt_authenckey_size(cc));

	return err;
}

#ifdef CONFIG_KEYS

static bool contains_whitespace(const char *str)
{
	while (*str)
		if (isspace(*str++))
			return true;
	return false;
}

static int set_key_user(struct crypt_config *cc, struct key *key)
{
	const struct user_key_payload *ukp;

	ukp = user_key_payload_locked(key);
	if (!ukp)
		return -EKEYREVOKED;

	if (cc->key_size != ukp->datalen)
		return -EINVAL;

	memcpy(cc->key, ukp->data, cc->key_size);

	return 0;
}

static int set_key_encrypted(struct crypt_config *cc, struct key *key)
{
	const struct encrypted_key_payload *ekp;

	ekp = key->payload.data[0];
	if (!ekp)
		return -EKEYREVOKED;

	if (cc->key_size != ekp->decrypted_datalen)
		return -EINVAL;

	memcpy(cc->key, ekp->decrypted_data, cc->key_size);

	return 0;
}

static int set_key_trusted(struct crypt_config *cc, struct key *key)
{
	const struct trusted_key_payload *tkp;

	tkp = key->payload.data[0];
	if (!tkp)
		return -EKEYREVOKED;

	if (cc->key_size != tkp->key_len)
		return -EINVAL;

	memcpy(cc->key, tkp->key, cc->key_size);

	return 0;
}

static int crypt_set_keyring_key(struct crypt_config *cc, const char *key_string)
{
	char *new_key_string, *key_desc;
	int ret;
	struct key_type *type;
	struct key *key;
	int (*set_key)(struct crypt_config *cc, struct key *key);

	/*
	 * Reject key_string with whitespace. dm core currently lacks code for
	 * proper whitespace escaping in arguments on DM_TABLE_STATUS path.
	 */
	if (contains_whitespace(key_string)) {
		DMERR("whitespace chars not allowed in key string");
		return -EINVAL;
	}

	/* look for next ':' separating key_type from key_description */
	key_desc = strpbrk(key_string, ":");
	if (!key_desc || key_desc == key_string || !strlen(key_desc + 1))
		return -EINVAL;

	if (!strncmp(key_string, "logon:", key_desc - key_string + 1)) {
		type = &key_type_logon;
		set_key = set_key_user;
	} else if (!strncmp(key_string, "user:", key_desc - key_string + 1)) {
		type = &key_type_user;
		set_key = set_key_user;
	} else if (IS_ENABLED(CONFIG_ENCRYPTED_KEYS) &&
			!strncmp(key_string, "encrypted:", key_desc - key_string + 1)) {
		type = &key_type_encrypted;
		set_key = set_key_encrypted;
	} else if (IS_ENABLED(CONFIG_TRUSTED_KEYS) &&
			!strncmp(key_string, "trusted:", key_desc - key_string + 1)) {
		type = &key_type_trusted;
		set_key = set_key_trusted;
	} else {
		return -EINVAL;
	}

	new_key_string = kstrdup(key_string, GFP_KERNEL);
	if (!new_key_string)
		return -ENOMEM;

	key = request_key(type, key_desc + 1, NULL);
	if (IS_ERR(key)) {
		kfree_sensitive(new_key_string);
		return PTR_ERR(key);
	}

	down_read(&key->sem);

	ret = set_key(cc, key);
	if (ret < 0) {
		up_read(&key->sem);
		key_put(key);
		kfree_sensitive(new_key_string);
		return ret;
	}

	up_read(&key->sem);
	key_put(key);

	/* clear the flag since following operations may invalidate previously valid key */
	clear_bit(DM_CRYPT_KEY_VALID, &cc->flags);

	ret = crypt_setkey(cc);

	if (!ret) {
		set_bit(DM_CRYPT_KEY_VALID, &cc->flags);
		kfree_sensitive(cc->key_string);
		cc->key_string = new_key_string;
	} else
		kfree_sensitive(new_key_string);

	return ret;
}

static int get_key_size(char **key_string)
{
	char *colon, dummy;
	int ret;

	if (*key_string[0] != ':')
		return strlen(*key_string) >> 1;

	/* look for next ':' in key string */
	colon = strpbrk(*key_string + 1, ":");
	if (!colon)
		return -EINVAL;

	if (sscanf(*key_string + 1, "%u%c", &ret, &dummy) != 2 || dummy != ':')
		return -EINVAL;

	*key_string = colon;

	/* remaining key string should be :<logon|user>:<key_desc> */

	return ret;
}

#else

static int crypt_set_keyring_key(struct crypt_config *cc, const char *key_string)
{
	return -EINVAL;
}

static int get_key_size(char **key_string)
{
	return (*key_string[0] == ':') ? -EINVAL : (int)(strlen(*key_string) >> 1);
}

#endif /* CONFIG_KEYS */

static int crypt_set_key(struct crypt_config *cc, char *key)
{
	int r = -EINVAL;
	int key_string_len = strlen(key);

	printk("key string is %s", key);

	/* Hyphen (which gives a key_size of zero) means there is no key. */
	if (!cc->key_size && strcmp(key, "-"))
	{
		goto out;
	}

	/* ':' means the key is in kernel keyring, short-circuit normal key processing */
	if (key[0] == ':') {
		r = crypt_set_keyring_key(cc, key + 1);
		goto out;
	}

	/* clear the flag since following operations may invalidate previously valid key */
	clear_bit(DM_CRYPT_KEY_VALID, &cc->flags);

	/* wipe references to any kernel keyring key */
	kfree_sensitive(cc->key_string);
	cc->key_string = NULL;

	/* Decode key from its hex representation. */
	if (cc->key_size && hex2bin(cc->key, key, cc->key_size) < 0)
	{
		goto out;
	}

	r = crypt_setkey(cc);
	if (!r)
		set_bit(DM_CRYPT_KEY_VALID, &cc->flags);

out:
	/* Hex key string not needed after here, so wipe it. */
	memset(key, '0', key_string_len);

	return r;
}

static int crypt_wipe_key(struct crypt_config *cc)
{
	int r;

	clear_bit(DM_CRYPT_KEY_VALID, &cc->flags);
	get_random_bytes(&cc->key, cc->key_size);

	/* Wipe IV private keys */
	if (cc->iv_gen_ops && cc->iv_gen_ops->wipe) {
		r = cc->iv_gen_ops->wipe(cc);
		if (r)
			return r;
	}

	kfree_sensitive(cc->key_string);
	cc->key_string = NULL;
	r = crypt_setkey(cc);
	memset(&cc->key, 0, cc->key_size * sizeof(u8));

	return r;
}

static void crypt_calculate_pages_per_client(void)
{
	unsigned long pages = (totalram_pages() - totalhigh_pages()) * DM_CRYPT_MEMORY_PERCENT / 100;

	if (!dm_crypt_clients_n)
		return;

	pages /= dm_crypt_clients_n;
	if (pages < DM_CRYPT_MIN_PAGES_PER_CLIENT)
		pages = DM_CRYPT_MIN_PAGES_PER_CLIENT;
	dm_crypt_pages_per_client = pages;
}

static void *crypt_page_alloc(gfp_t gfp_mask, void *pool_data)
{
	struct crypt_config *cc = pool_data;
	struct page *page;

	/*
	 * Note, percpu_counter_read_positive() may over (and under) estimate
	 * the current usage by at most (batch - 1) * num_online_cpus() pages,
	 * but avoids potential spinlock contention of an exact result.
	 */
	if (unlikely(percpu_counter_read_positive(&cc->n_allocated_pages) >= dm_crypt_pages_per_client) &&
			likely(gfp_mask & __GFP_NORETRY))
		return NULL;

	page = alloc_page(gfp_mask);
	if (likely(page != NULL))
		percpu_counter_add(&cc->n_allocated_pages, 1);

	return page;
}

static void crypt_page_free(void *page, void *pool_data)
{
	struct crypt_config *cc = pool_data;

	__free_page(page);
	percpu_counter_sub(&cc->n_allocated_pages, 1);
}

static void crypt_dtr(struct dm_target *ti)
{
	struct crypt_config *cc = ti->private;

	ti->private = NULL;

	if (!cc)
		return;

	if (cc->write_thread)
		kthread_stop(cc->write_thread);
	if (cc->io_queue)
		destroy_workqueue(cc->io_queue);
	if (cc->crypt_queue)
		destroy_workqueue(cc->crypt_queue);

	file_close(bio_file);

	crypt_free_tfms(cc);

	bioset_exit(&cc->bs);

	mempool_exit(&cc->page_pool);
	mempool_exit(&cc->req_pool);
	mempool_exit(&cc->tag_pool);

	WARN_ON(percpu_counter_sum(&cc->n_allocated_pages) != 0);
	percpu_counter_destroy(&cc->n_allocated_pages);

	if (cc->iv_gen_ops && cc->iv_gen_ops->dtr)
		cc->iv_gen_ops->dtr(cc);

	if (cc->dev)
		dm_put_device(ti, cc->dev);

	kfree_sensitive(cc->cipher_string);
	kfree_sensitive(cc->key_string);
	kfree_sensitive(cc->cipher_auth);
	kfree_sensitive(cc->authenc_key);

	mutex_destroy(&cc->bio_alloc_lock);

	/* Must zero key material before freeing */
	kfree_sensitive(cc);

	spin_lock(&dm_crypt_clients_lock);
	WARN_ON(!dm_crypt_clients_n);
	dm_crypt_clients_n--;
	crypt_calculate_pages_per_client();
	spin_unlock(&dm_crypt_clients_lock);

	dm_audit_log_dtr(DM_MSG_PREFIX, ti, 1);

	idr_destroy(&map_idr);
}

static int crypt_ctr_ivmode(struct dm_target *ti, const char *ivmode)
{
	struct crypt_config *cc = ti->private;

	if (crypt_integrity_aead(cc))
		cc->iv_size = crypto_aead_ivsize(any_tfm_aead(cc));
	else
		cc->iv_size = crypto_skcipher_ivsize(any_tfm(cc));

	if (cc->iv_size)
		/* at least a 64 bit sector number should fit in our buffer */
		cc->iv_size = max(cc->iv_size,
				(unsigned int)(sizeof(u64) / sizeof(u8)));
	else if (ivmode) {
		DMWARN("Selected cipher does not support IVs");
		ivmode = NULL;
	}

	/* Choose ivmode, see comments at iv code. */
	if (ivmode == NULL)
		cc->iv_gen_ops = NULL;
	else if (strcmp(ivmode, "plain") == 0)
		cc->iv_gen_ops = &crypt_iv_plain_ops;
	else if (strcmp(ivmode, "plain64") == 0)
		cc->iv_gen_ops = &crypt_iv_plain64_ops;
	else if (strcmp(ivmode, "plain64be") == 0)
		cc->iv_gen_ops = &crypt_iv_plain64be_ops;
	else if (strcmp(ivmode, "essiv") == 0)
		cc->iv_gen_ops = &crypt_iv_essiv_ops;
	else if (strcmp(ivmode, "benbi") == 0)
		cc->iv_gen_ops = &crypt_iv_benbi_ops;
	else if (strcmp(ivmode, "null") == 0)
		cc->iv_gen_ops = &crypt_iv_null_ops;
	else if (strcmp(ivmode, "eboiv") == 0)
		cc->iv_gen_ops = &crypt_iv_eboiv_ops;
	else if (strcmp(ivmode, "elephant") == 0) {
		cc->iv_gen_ops = &crypt_iv_elephant_ops;
		cc->key_parts = 2;
		cc->key_extra_size = cc->key_size / 2;
		if (cc->key_extra_size > ELEPHANT_MAX_KEY_SIZE)
			return -EINVAL;
		set_bit(CRYPT_ENCRYPT_PREPROCESS, &cc->cipher_flags);
	} else if (strcmp(ivmode, "lmk") == 0) {
		cc->iv_gen_ops = &crypt_iv_lmk_ops;
		/*
		 * Version 2 and 3 is recognised according
		 * to length of provided multi-key string.
		 * If present (version 3), last key is used as IV seed.
		 * All keys (including IV seed) are always the same size.
		 */
		if (cc->key_size % cc->key_parts) {
			cc->key_parts++;
			cc->key_extra_size = cc->key_size / cc->key_parts;
		}
	} else if (strcmp(ivmode, "tcw") == 0) {
		cc->iv_gen_ops = &crypt_iv_tcw_ops;
		cc->key_parts += 2; /* IV + whitening */
		cc->key_extra_size = cc->iv_size + TCW_WHITENING_SIZE;
	} else if (strcmp(ivmode, "random") == 0) {
		cc->iv_gen_ops = &crypt_iv_random_ops;
		/* Need storage space in integrity fields. */
		cc->integrity_iv_size = cc->iv_size;
	} else {
		ti->error = "Invalid IV mode";
		return -EINVAL;
	}

	return 0;
}

/*
 * Workaround to parse HMAC algorithm from AEAD crypto API spec.
 * The HMAC is needed to calculate tag size (HMAC digest size).
 * This should be probably done by crypto-api calls (once available...)
 */
static int crypt_ctr_auth_cipher(struct crypt_config *cc, char *cipher_api)
{
	char *start, *end, *mac_alg = NULL;
	struct crypto_ahash *mac;

	if (!strstarts(cipher_api, "authenc("))
		return 0;

	start = strchr(cipher_api, '(');
	end = strchr(cipher_api, ',');
	if (!start || !end || ++start > end)
		return -EINVAL;

	mac_alg = kzalloc(end - start + 1, GFP_KERNEL);
	if (!mac_alg)
		return -ENOMEM;
	strncpy(mac_alg, start, end - start);

	mac = crypto_alloc_ahash(mac_alg, 0, CRYPTO_ALG_ALLOCATES_MEMORY);
	kfree(mac_alg);

	if (IS_ERR(mac))
		return PTR_ERR(mac);

	cc->key_mac_size = crypto_ahash_digestsize(mac);
	crypto_free_ahash(mac);

	cc->authenc_key = kmalloc(crypt_authenckey_size(cc), GFP_KERNEL);
	if (!cc->authenc_key)
		return -ENOMEM;

	return 0;
}

static int crypt_ctr_cipher_new(struct dm_target *ti, char *cipher_in, char *key,
		char **ivmode, char **ivopts)
{
	struct crypt_config *cc = ti->private;
	char *tmp, *cipher_api, buf[CRYPTO_MAX_ALG_NAME];
	int ret = -EINVAL;

	cc->tfms_count = 1;

	/*
	 * New format (capi: prefix)
	 * capi:cipher_api_spec-iv:ivopts
	 */
	tmp = &cipher_in[strlen("capi:")];

	/* Separate IV options if present, it can contain another '-' in hash name */
	*ivopts = strrchr(tmp, ':');
	if (*ivopts) {
		**ivopts = '\0';
		(*ivopts)++;
	}
	/* Parse IV mode */
	*ivmode = strrchr(tmp, '-');
	if (*ivmode) {
		**ivmode = '\0';
		(*ivmode)++;
	}
	/* The rest is crypto API spec */
	cipher_api = tmp;

	/* Alloc AEAD, can be used only in new format. */
	if (crypt_integrity_aead(cc)) {
		ret = crypt_ctr_auth_cipher(cc, cipher_api);
		if (ret < 0) {
			ti->error = "Invalid AEAD cipher spec";
			return -ENOMEM;
		}
	}

	if (*ivmode && !strcmp(*ivmode, "lmk"))
		cc->tfms_count = 64;

	if (*ivmode && !strcmp(*ivmode, "essiv")) {
		if (!*ivopts) {
			ti->error = "Digest algorithm missing for ESSIV mode";
			return -EINVAL;
		}
		ret = snprintf(buf, CRYPTO_MAX_ALG_NAME, "essiv(%s,%s)",
				cipher_api, *ivopts);
		if (ret < 0 || ret >= CRYPTO_MAX_ALG_NAME) {
			ti->error = "Cannot allocate cipher string";
			return -ENOMEM;
		}
		cipher_api = buf;
	}

	cc->key_parts = cc->tfms_count;

	/* Allocate cipher */
	ret = crypt_alloc_tfms(cc, cipher_api);
	if (ret < 0) {
		ti->error = "Error allocating crypto tfm";
		return ret;
	}

	if (crypt_integrity_aead(cc))
		cc->iv_size = crypto_aead_ivsize(any_tfm_aead(cc));
	else
		cc->iv_size = crypto_skcipher_ivsize(any_tfm(cc));

	return 0;
}

static int crypt_ctr_cipher_old(struct dm_target *ti, char *cipher_in, char *key,
		char **ivmode, char **ivopts)
{
	struct crypt_config *cc = ti->private;
	char *tmp, *cipher, *chainmode, *keycount;
	char *cipher_api = NULL;
	int ret = -EINVAL;
	char dummy;

	if (strchr(cipher_in, '(') || crypt_integrity_aead(cc)) {
		ti->error = "Bad cipher specification";
		return -EINVAL;
	}

	/*
	 * Legacy dm-crypt cipher specification
	 * cipher[:keycount]-mode-iv:ivopts
	 */
	tmp = cipher_in;
	keycount = strsep(&tmp, "-");
	cipher = strsep(&keycount, ":");

	if (!keycount)
		cc->tfms_count = 1;
	else if (sscanf(keycount, "%u%c", &cc->tfms_count, &dummy) != 1 ||
			!is_power_of_2(cc->tfms_count)) {
		ti->error = "Bad cipher key count specification";
		return -EINVAL;
	}
	cc->key_parts = cc->tfms_count;

	chainmode = strsep(&tmp, "-");
	*ivmode = strsep(&tmp, ":");
	*ivopts = tmp;

	/*
	 * For compatibility with the original dm-crypt mapping format, if
	 * only the cipher name is supplied, use cbc-plain.
	 */
	if (!chainmode || (!strcmp(chainmode, "plain") && !*ivmode)) {
		chainmode = "cbc";
		*ivmode = "plain";
	}

	if (strcmp(chainmode, "ecb") && !*ivmode) {
		ti->error = "IV mechanism required";
		return -EINVAL;
	}

	cipher_api = kmalloc(CRYPTO_MAX_ALG_NAME, GFP_KERNEL);
	if (!cipher_api)
		goto bad_mem;

	if (*ivmode && !strcmp(*ivmode, "essiv")) {
		if (!*ivopts) {
			ti->error = "Digest algorithm missing for ESSIV mode";
			kfree(cipher_api);
			return -EINVAL;
		}
		ret = snprintf(cipher_api, CRYPTO_MAX_ALG_NAME,
				"essiv(%s(%s),%s)", chainmode, cipher, *ivopts);
	} else {
		ret = snprintf(cipher_api, CRYPTO_MAX_ALG_NAME,
				"%s(%s)", chainmode, cipher);
	}
	if (ret < 0 || ret >= CRYPTO_MAX_ALG_NAME) {
		kfree(cipher_api);
		goto bad_mem;
	}

	/* Allocate cipher */
	ret = crypt_alloc_tfms(cc, cipher_api);
	if (ret < 0) {
		ti->error = "Error allocating crypto tfm";
		kfree(cipher_api);
		return ret;
	}
	kfree(cipher_api);

	return 0;
bad_mem:
	ti->error = "Cannot allocate cipher strings";
	return -ENOMEM;
}

static int crypt_ctr_cipher(struct dm_target *ti, char *cipher_in, char *key)
{
	struct crypt_config *cc = ti->private;
	char *ivmode = NULL, *ivopts = NULL;
	int ret;

	cc->cipher_string = kstrdup(cipher_in, GFP_KERNEL);
	if (!cc->cipher_string) {
		ti->error = "Cannot allocate cipher strings";
		return -ENOMEM;
	}

	if (strstarts(cipher_in, "capi:"))
		ret = crypt_ctr_cipher_new(ti, cipher_in, key, &ivmode, &ivopts);
	else
		ret = crypt_ctr_cipher_old(ti, cipher_in, key, &ivmode, &ivopts);
	if (ret)
		return ret;

	/* Initialize IV */
	ret = crypt_ctr_ivmode(ti, ivmode);
	if (ret < 0)
		return ret;

	/* Initialize and set key */
	ret = crypt_set_key(cc, key);
	if (ret < 0) {
		ti->error = "Error decoding and setting key";
		return ret;
	}

	/* Allocate IV */
	if (cc->iv_gen_ops && cc->iv_gen_ops->ctr) {
		ret = cc->iv_gen_ops->ctr(cc, ti, ivopts);
		if (ret < 0) {
			ti->error = "Error creating IV";
			return ret;
		}
	}

	/* Initialize IV (set keys for ESSIV etc) */
	if (cc->iv_gen_ops && cc->iv_gen_ops->init) {
		ret = cc->iv_gen_ops->init(cc);
		if (ret < 0) {
			ti->error = "Error initialising IV";
			return ret;
		}
	}

	/* wipe the kernel key payload copy */
	if (cc->key_string)
		memset(cc->key, 0, cc->key_size * sizeof(u8));

	return ret;
}

static int crypt_ctr_optional(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct crypt_config *cc = ti->private;
	struct dm_arg_set as;
	static const struct dm_arg _args[] = {
		{0, 8, "Invalid number of feature args"},
	};
	unsigned int opt_params, val;
	const char *opt_string, *sval;
	char dummy;
	int ret;

	/* Optional parameters */
	as.argc = argc;
	as.argv = argv;

	ret = dm_read_arg_group(_args, &as, &opt_params, &ti->error);
	if (ret)
		return ret;

	while (opt_params--) {
		opt_string = dm_shift_arg(&as);
		if (!opt_string) {
			ti->error = "Not enough feature arguments";
			return -EINVAL;
		}

		if (!strcasecmp(opt_string, "allow_discards"))
			ti->num_discard_bios = 1;

		else if (!strcasecmp(opt_string, "same_cpu_crypt"))
			set_bit(DM_CRYPT_SAME_CPU, &cc->flags);

		else if (!strcasecmp(opt_string, "submit_from_crypt_cpus"))
			set_bit(DM_CRYPT_NO_OFFLOAD, &cc->flags);
		else if (!strcasecmp(opt_string, "no_read_workqueue"))
			set_bit(DM_CRYPT_NO_READ_WORKQUEUE, &cc->flags);
		else if (!strcasecmp(opt_string, "no_write_workqueue"))
			set_bit(DM_CRYPT_NO_WRITE_WORKQUEUE, &cc->flags);
		else if (sscanf(opt_string, "integrity:%u:", &val) == 1) {
			if (val == 0 || val > MAX_TAG_SIZE) {
				ti->error = "Invalid integrity arguments";
				return -EINVAL;
			}
			cc->on_disk_tag_size = val;
			sval = strchr(opt_string + strlen("integrity:"), ':') + 1;
			if (!strcasecmp(sval, "aead")) {
				set_bit(CRYPT_MODE_INTEGRITY_AEAD, &cc->cipher_flags);
			} else  if (strcasecmp(sval, "none")) {
				ti->error = "Unknown integrity profile";
				return -EINVAL;
			}

			cc->cipher_auth = kstrdup(sval, GFP_KERNEL);
			if (!cc->cipher_auth)
				return -ENOMEM;
		} else if (sscanf(opt_string, "sector_size:%hu%c", &cc->sector_size, &dummy) == 1) {
			if (cc->sector_size < (1 << SECTOR_SHIFT) ||
					cc->sector_size > 4096 ||
					(cc->sector_size & (cc->sector_size - 1))) {
				ti->error = "Invalid feature value for sector_size";
				return -EINVAL;
			}
			if (ti->len & ((cc->sector_size >> SECTOR_SHIFT) - 1)) {
				ti->error = "Device size is not multiple of sector_size feature";
				return -EINVAL;
			}
			cc->sector_shift = __ffs(cc->sector_size) - SECTOR_SHIFT;
		} else if (!strcasecmp(opt_string, "iv_large_sectors"))
			set_bit(CRYPT_IV_LARGE_SECTORS, &cc->cipher_flags);
		else if (sscanf(opt_string, "store_data_in_integrity_md:%u", &val) == 1) {
			set_bit(DM_CRYPT_STORE_DATA_IN_INTEGRITY_MD, &cc->flags);
			if (val == 0 || val > MAX_TAG_SIZE) {
				ti->error = "Invalid integrity arguments";
				return -EINVAL;
			}
			cc->on_disk_tag_size = val;
		} else {
			ti->error = "Invalid feature arguments";
			return -EINVAL;
		}
	}

	return 0;
}

#ifdef CONFIG_BLK_DEV_ZONED
static int crypt_report_zones(struct dm_target *ti,
		struct dm_report_zones_args *args, unsigned int nr_zones)
{
	struct crypt_config *cc = ti->private;

	return dm_report_zones(cc->dev->bdev, cc->start,
			cc->start + dm_target_offset(ti, args->next_sector),
			args, nr_zones);
}
#else
#define crypt_report_zones NULL
#endif


//gets IV data for sectors starting from "sector". Count should not exceed 32768
void get_ivs_from_sector(struct dm_crypt_io *io, sector_t sector, unsigned char *tag, int tag_size)
{
	struct crypt_config *cc = io->cc;
        int nr_iovecs = (tag_size + PAGE_SIZE - 1) >> PAGE_SHIFT;
        struct bio *bio = bio_alloc_bioset(cc->dev->bdev, nr_iovecs, REQ_OP_READ, GFP_NOIO, &cc->bs);
	unsigned int flags = io->flags;
	struct convert_context lctx = io->ctx;
	unsigned i, len, remaining_size;
	struct page *page;
	gfp_t gfp_mask = GFP_NOWAIT | __GFP_HIGHMEM;
	int r = 0;
	int tag_offset = 0;

	printk("get_ivs_from_sector, getting %d IVs starting from %d\n", tag_size/IV_SIZE, sector);

        if (unlikely(!bio)) {
                io->error = BLK_STS_IOERR;
                printk("get_ivs_from_sector, Error allocating bio");
                return;
        }
        remaining_size = tag_size;

        for (i = 0; i < nr_iovecs; i++) {
                page = mempool_alloc(&cc->page_pool, gfp_mask);
                if (!page) {
                        printk("Error allocating a page");
                        return;
                }

                len = (remaining_size > PAGE_SIZE) ? PAGE_SIZE : remaining_size;

                r = bio_add_page(bio, page, len, 0);

                remaining_size -= len;
        }
        bio->bi_opf = REQ_OP_READ;
        io->flags = PD_HIDDEN_OPERATION | PD_READ_MAP_DATA;

	memset(tag, 0, tag_size);
	get_map_data(sector, tag, tag_size, NULL);

        struct bvec_iter iter_out = bio->bi_iter;
        unsigned offset = 0;
        while (iter_out.bi_size) {
              struct bio_vec bv_out = bio_iter_iovec(bio, iter_out);
              char *buffer = page_to_virt(bv_out.bv_page);

              memcpy(buffer + bv_out.bv_offset, tag + offset, cc->on_disk_tag_size);
              bio_advance_iter(bio, &iter_out, cc->on_disk_tag_size);
              offset += cc->on_disk_tag_size;
        }
        crypt_convert_init(cc, &io->ctx, bio, bio, sector, &tag_offset);
        r = crypt_convert(cc, &io->ctx,
                          test_bit(DM_CRYPT_NO_READ_WORKQUEUE, &cc->flags), true);
        if (r){
              printk("crypt_convert failed");
              io->error = r; //TODO: free everything and return failure
        }
        iter_out = bio->bi_iter;
        offset = 0;
        //print_bio("Data during initialization", bio);
        while (iter_out.bi_size) {
            struct bio_vec bv_out = bio_iter_iovec(bio, iter_out);
            char *buffer = page_to_virt(bv_out.bv_page);
	    memcpy(tag + offset, buffer, cc->on_disk_tag_size);
            bio_advance_iter(bio, &iter_out, cc->on_disk_tag_size);
            offset += cc->on_disk_tag_size;
         }

	//restore old io values
	io->flags = flags;
	io->ctx = lctx;
        crypt_free_buffer_pages(cc, bio);
        bio_put(bio);
}

static void map_endio(struct bio *clone)
{
        struct dm_crypt_io *io = clone->bi_private;
        struct crypt_config *cc = io->cc;
        unsigned rw = bio_data_dir(clone);

        //printk("Inside map_endio IO address %p, IO flags %d, size= %d, starting sector = %d, direction %s\n",
        //               io, io->flags, clone->bi_iter.bi_size, clone->bi_iter.bi_sector, (rw == WRITE) ? "WRITE" : "READ");
        complete(&io->map_complete);
}

static int read_sector_metadata(struct dm_crypt_io *io, struct bio *base_bio, sector_t sector, unsigned char *data, unsigned size)
{
        int ret = 0;
        int r;
        struct crypt_config *cc = io->cc;
        unsigned int flags = io->flags;
        struct convert_context lctx = io->ctx;


                // Read equivalent data sectors along with integrity metadata
                int tag_offset = 0;
                unsigned len = (size / cc->on_disk_tag_size) * cc->sector_size;
                struct bio *bio = crypt_alloc_buffer(io, len, 0);
                bio->bi_private = io;
                bio->bi_end_io = map_endio;
                bio->bi_opf = REQ_OP_READ | REQ_INTEGRITY;
                bio->bi_iter.bi_sector = sector;
                crypt_inc_pending(io);
                dm_submit_bio_remap(base_bio, bio);
                wait_for_completion(&io->map_complete);
                reinit_completion(&io->map_complete);

                //decrypt the integrity metadata
                struct bio *hbio = crypt_alloc_buffer(io, size, 0);
                struct bvec_iter iter_out = hbio->bi_iter;
                unsigned offset = 0;
                while (iter_out.bi_size) {
                        struct bio_vec bv_out = bio_iter_iovec(hbio, iter_out);
                        char *buffer = page_to_virt(bv_out.bv_page);

                        memcpy(buffer + bv_out.bv_offset, io->integrity_metadata + offset, size);
                        bio_advance_iter(hbio, &iter_out, size);
                        offset += size;
                }
                hbio->bi_opf = REQ_OP_READ;
                io->flags = PD_HIDDEN_OPERATION | PD_READ_MAP_DATA;
                crypt_convert_init(cc, &io->ctx, hbio, hbio, sector, &tag_offset);
                r = crypt_convert(cc, &io->ctx, false, true);

                // copy decrypted data to output
                iter_out = hbio->bi_iter;
                offset = 0;
                while (iter_out.bi_size) {
                        struct bio_vec bv_out = bio_iter_iovec(hbio, iter_out);
                        char *buffer = page_to_virt(bv_out.bv_page);

                        memcpy(data + offset, buffer + bv_out.bv_offset, size);
                        bio_advance_iter(hbio, &iter_out, size);
                        offset += size;
                }
                crypt_free_buffer_pages(cc, bio);
                bio_put(bio);
                crypt_free_buffer_pages(cc, hbio);
                bio_put(hbio);
                crypt_dec_pending(io);
        //restore old io values
        io->flags = flags;
        io->ctx = lctx;

        return ret;
}

struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
    struct sdesc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    return sdesc;
}

static int calc_hash(struct crypto_shash *alg,
             const unsigned char *data, unsigned int datalen,
             unsigned char *digest)
{
    struct sdesc *sdesc;
    int ret;

    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc)) {
        pr_info("can't alloc sdesc\n");
        return PTR_ERR(sdesc);
    }

    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    kfree(sdesc);
    return ret;
}

static int test_hash(const unsigned char *data, unsigned int datalen,
             unsigned char *digest)
{
    struct crypto_shash *alg;
    char *hash_alg_name = "sha256";
    int ret;

    alg = crypto_alloc_shash(hash_alg_name, 0, 0);
    if (IS_ERR(alg)) {
            pr_info("can't alloc alg %s\n", hash_alg_name);
            return PTR_ERR(alg);
    }
    ret = calc_hash(alg, data, datalen, digest);
    crypto_free_shash(alg);
    return ret;
}

void get_IVs(struct crypt_config *cc, sector_t sector, unsigned char *tag, int tag_size)
{
        struct dm_crypt_io *io; //dummy io object. needed as crypt_convert depends on it for few members. not elegant
        int tag_offset = 0;
        struct bio *bio;
        unsigned int nr_iovecs;
        gfp_t gfp_mask = GFP_NOWAIT | __GFP_HIGHMEM;
        unsigned i, len, remaining_size;
        struct page *page;
        int ret = 0;

        io = (struct dm_crypt_io *)kmalloc(cc->per_bio_data_size, GFP_KERNEL);

        io->cc = cc;

        nr_iovecs = (tag_size + PAGE_SIZE - 1) >> PAGE_SHIFT;
        bio = bio_alloc_bioset(cc->dev->bdev, nr_iovecs, REQ_OP_READ, GFP_NOIO, &cc->bs);
        if (unlikely(!bio)) {
                io->error = BLK_STS_IOERR;
                printk("map_common, Error allocating bio");
                return;
        }
        remaining_size = tag_size;

        for (i = 0; i < nr_iovecs; i++) {
                page = mempool_alloc(&cc->page_pool, gfp_mask);
                if (!page) {
                        printk("Error allocating a page");
                        return;
                }

                len = (remaining_size > PAGE_SIZE) ? PAGE_SIZE : remaining_size;

                ret = bio_add_page(bio, page, len, 0);

                remaining_size -= len;
        }
        bio->bi_opf = REQ_OP_READ;
        io->flags |= PD_HIDDEN_OPERATION | PD_READ_MAP_DATA;

        memset(tag, 0, tag_size);
        get_map_data(sector, tag, tag_size, NULL);
        //printk("map_common sector %d, tag[0] = %02hhx, tag[1] = %02hhx, tag[2] = %02hhx, tag[3] = %02hhx, tag[4] = %02hhx\n",
        //              current_sector, tag[0], tag[1], tag[2], tag[3], tag[4]);
        if (crypt_integrity_aead(cc))
                io->ctx.r.req_aead = (struct aead_request *)(io + 1);
        else
                io->ctx.r.req = (struct skcipher_request *)(io + 1);

        struct bvec_iter iter_out = bio->bi_iter;
        unsigned offset = 0;
        while (iter_out.bi_size) {
                struct bio_vec bv_out = bio_iter_iovec(bio, iter_out);
                char *buffer = page_to_virt(bv_out.bv_page);

                memcpy(buffer + bv_out.bv_offset, tag + offset, cc->on_disk_tag_size);
                bio_advance_iter(bio, &iter_out, cc->on_disk_tag_size);
                offset += cc->on_disk_tag_size;
        }

        crypt_convert_init(cc, &io->ctx, bio, bio, sector, &tag_offset);
        int r = crypt_convert(cc, &io->ctx,
                        test_bit(DM_CRYPT_NO_READ_WORKQUEUE, &cc->flags), true);
        if (r){
                printk("crypt_convert failed");
                io->error = r; //TODO: free everything and return failure
        }
        iter_out = bio->bi_iter;
        offset = 0;
        //print_bio("Data during initialization", bio);
        while (iter_out.bi_size) {
                struct bio_vec bv_out = bio_iter_iovec(bio, iter_out);
                char *buffer = page_to_virt(bv_out.bv_page);
		memcpy(tag + offset, buffer + bv_out.bv_offset, cc->on_disk_tag_size);
                bio_advance_iter(bio, &iter_out, cc->on_disk_tag_size);
                offset += cc->on_disk_tag_size;
        }
        crypt_free_buffer_pages(cc, bio);
        bio_put(bio);
        kfree(io);
}

void map_common(struct crypt_config *cc, sector_t start, sector_t end)
{
        sector_t current_sector = start;
        unsigned max_sectors = end;
        unsigned char tag[IV_SIZE];
	unsigned int tag_size = IV_SIZE;
        int iv_offset = 0;
        unsigned sector_num = 0;
        unsigned short sequence_num = 0;
        unsigned map_pub_sector = 0;
        unsigned char sanity_ivs[2*IV_SIZE] = {0};
        unsigned char *iv1 = sanity_ivs, *iv2 = sanity_ivs + IV_SIZE;
	int increment_index;

	printk("map_common, entering\n");

        while(current_sector < max_sectors) {
                memset(tag, 0, tag_size);
                get_IVs(cc, current_sector, tag, tag_size);
		increment_index = NUM_PUBLIC_SECTORS_PER_HIDDEN_SECTOR;
                //printk("map_common sector %d, tag[0] = %02hhx, tag[1] = %02hhx, tag[2] = %02hhx, tag[3] = %02hhx, tag[4] = %02hhx\n",
                //              current_sector, tag[0], tag[1], tag[2], tag[3], tag[4]);
		
                if ((unsigned char)tag[PD_MAGIC_DATA_POS] == PD_MAGIC_DATA) {
                        iv_offset = (unsigned char)tag[IV_OFFSET_POS];
                        if (iv_offset == 0) {
				/* get next two IVs and confirm their sanity. IV offsets and PWC check */
                                get_IVs(cc, current_sector + 1, sanity_ivs, sizeof(sanity_ivs));
                                if (iv1[PD_MAGIC_DATA_POS] != PD_MAGIC_DATA || iv2[PD_MAGIC_DATA_POS] != PD_MAGIC_DATA ||
                                    iv1[IV_OFFSET_POS] != 1 || iv2[IV_OFFSET_POS] != 2 ||
                                    iv1[RANDOM_BYTES_POS] != iv2[RANDOM_BYTES_POS] ||
                                    iv1[RANDOM_BYTES_POS + 1] != iv2[RANDOM_BYTES_POS])
                                        goto next;
				//all good. extract the data from tag
                                int HIDDEN_BYTES_PER_TAG = HIDDEN_BYTES_IN_FIRST_IV;
                                memcpy(&sector_num, tag + HIDDEN_BYTES_PER_TAG, SECTOR_NUM_LEN);
                                memcpy(&sequence_num , tag + HIDDEN_BYTES_PER_TAG + SECTOR_NUM_LEN, SEQUENCE_NUMBER_LEN);
                                map_pub_sector = current_sector;
                        }
			else {
				if (iv_offset >= NUM_PUBLIC_SECTORS_PER_HIDDEN_SECTOR || (current_sector - iv_offset) < 0)
					goto next;
				/* get first two IVs in the sequence and check their sanity */
				get_IVs(cc, current_sector - iv_offset, sanity_ivs, sizeof(sanity_ivs));
				if (iv1[PD_MAGIC_DATA_POS] != PD_MAGIC_DATA || iv2[PD_MAGIC_DATA_POS] != PD_MAGIC_DATA ||
				    iv1[IV_OFFSET_POS] != 0 || iv2[IV_OFFSET_POS] != 1 ||
				    iv1[RANDOM_BYTES_POS] != iv2[RANDOM_BYTES_POS] ||
				    iv1[RANDOM_BYTES_POS + 1] != iv2[RANDOM_BYTES_POS])
					goto next;
				//everything is fine so far. extract data from iv1
                                int HIDDEN_BYTES_PER_TAG = HIDDEN_BYTES_IN_FIRST_IV;
                                memcpy(&sector_num, iv1 + HIDDEN_BYTES_PER_TAG, SECTOR_NUM_LEN);
                                memcpy(&sequence_num , iv1 + HIDDEN_BYTES_PER_TAG + SECTOR_NUM_LEN, SEQUENCE_NUMBER_LEN);
                                map_pub_sector = current_sector - iv_offset;
				increment_index = NUM_PUBLIC_SECTORS_PER_HIDDEN_SECTOR - iv_offset;
			}

                        unsigned short current_sequence_num;
                        if (map_find(sector_num, &current_sequence_num, NULL) != -1) {
                                 if(sequence_num > current_sequence_num) {
                                        printk("map_common, updating logical sector %d, physical sector %d, sequence_num %u, current_seq %u\n",
                                                sector_num, map_pub_sector, sequence_num, current_sequence_num);
                                        map_insert(sector_num, map_pub_sector, &sequence_num, false);
                                 }
                        }
                        else {
                                printk("map_common, inserting logical sector %d, physical sector %d, sequence_num %u\n",
                                        sector_num, map_pub_sector, sequence_num);
                                map_insert(sector_num, map_pub_sector, &sequence_num, false);
                        }
                }
next:
                current_sector += increment_index;
        }

        printk("map_common exiting\n");
}

struct my_struct {
	struct crypt_config *cc;
	unsigned max_sectors;
	int index;
};
#define MAX_THREADS 12 //tested with 6 cores 
static int map_data_thread(void *data)
{
	struct my_struct *mys = (struct my_struct *)data;
	//printk("map_data_thread %d, entering!\n", mys->index);
	map_common(mys->cc, (mys->max_sectors * mys->index)/MAX_THREADS, ((mys->max_sectors * (mys->index + 1))/MAX_THREADS) - 1);
	printk("map_data_thread %d, exiting!\n", mys->index);
	return 0;
}

struct my_struct mys[MAX_THREADS];
void process_map_data(struct crypt_config *cc)
{
	unsigned max_sectors = 0;
	static struct task_struct *map_thread;
	int i;

	printk("process_map_data, entering");
	get_map_data(0, 0, 0, &max_sectors); 
	printk("process_map_data, max_sectors %d\n", max_sectors);

	for (i = 0; i < MAX_THREADS - 1; i++) {
		mys[i].index = i;
		mys[i].cc = cc;
		mys[i].max_sectors = max_sectors;
        	map_thread = kthread_run(map_data_thread, &mys[i], "map_data_thread", NULL);
        	if (IS_ERR(map_thread)) {
			printk("process_map_data, error spawning map_thread");
			return;
        	}
	}

	map_common(cc, (max_sectors * (MAX_THREADS - 1))/MAX_THREADS, max_sectors -1);
	printk("process_map_data decrypted integrity metadata\n");
}

/*
 * Construct an encryption mapping:
 * <cipher> [<key>|:<key_size>:<user|logon>:<key_description>] <iv_offset> <dev_path> <start>
 */
static int crypt_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct crypt_config *cc;
	const char *devname = dm_table_device_name(ti->table);
	int key_size;
	unsigned int align_mask;
	unsigned long long tmpll;
	int ret, i;
	size_t iv_size_padding, additional_req_size;
	char dummy;

	printk("device name %s, begin %d, len %d\n", devname, ti->begin, ti->len);
	if (argc < 5) {
		ti->error = "Not enough arguments";
		return -EINVAL;
	}

	for(i = 0; i < argc; i++)
		printk("[%d] = %s", i, argv[i]);

	key_size = get_key_size(&argv[1]);
	if (key_size < 0) {
		ti->error = "Cannot parse key size";
		return -EINVAL;
	}

	printk("key size = %d", key_size);

	cc = kzalloc(struct_size(cc, key, key_size), GFP_KERNEL);
	if (!cc) {
		ti->error = "Cannot allocate encryption context";
		return -ENOMEM;
	}
	cc->key_size = key_size;
	cc->sector_size = (1 << SECTOR_SHIFT);
	cc->sector_shift = 0;

	ti->private = cc;

	spin_lock(&dm_crypt_clients_lock);
	dm_crypt_clients_n++;
	crypt_calculate_pages_per_client();
	spin_unlock(&dm_crypt_clients_lock);

	ret = percpu_counter_init(&cc->n_allocated_pages, 0, GFP_KERNEL);
	if (ret < 0)
		goto bad;

	/* Optional parameters need to be read before cipher constructor */
	if (argc > 5) {
		ret = crypt_ctr_optional(ti, argc - 5, &argv[5]);
		if (ret)
			goto bad;
	}

	ret = crypt_ctr_cipher(ti, argv[0], argv[1]);
	if (ret < 0)
		goto bad;

	if (crypt_integrity_aead(cc)) {
		cc->dmreq_start = sizeof(struct aead_request);
		cc->dmreq_start += crypto_aead_reqsize(any_tfm_aead(cc));
		align_mask = crypto_aead_alignmask(any_tfm_aead(cc));
	} else {
		cc->dmreq_start = sizeof(struct skcipher_request);
		cc->dmreq_start += crypto_skcipher_reqsize(any_tfm(cc));
		align_mask = crypto_skcipher_alignmask(any_tfm(cc));
	}
	cc->dmreq_start = ALIGN(cc->dmreq_start, __alignof__(struct dm_crypt_request));
	printk("dmreq_start is %d\n", cc->dmreq_start);

	if (align_mask < CRYPTO_MINALIGN) {
		/* Allocate the padding exactly */
		iv_size_padding = -(cc->dmreq_start + sizeof(struct dm_crypt_request))
			& align_mask;
	} else {
		/*
		 * If the cipher requires greater alignment than kmalloc
		 * alignment, we don't know the exact position of the
		 * initialization vector. We must assume worst case.
		 */
		iv_size_padding = align_mask;
	}
	printk("IV size padding %ld\n", iv_size_padding);

	/*  ...| IV + padding | original IV | original sec. number | bio tag offset | */
	additional_req_size = sizeof(struct dm_crypt_request) +
		iv_size_padding + cc->iv_size +
		cc->iv_size +
		sizeof(uint64_t) +
		sizeof(unsigned int);
	printk("additional_req_size %ld\n", additional_req_size);

	ret = mempool_init_kmalloc_pool(&cc->req_pool, MIN_IOS, cc->dmreq_start + additional_req_size);
	if (ret) {
		ti->error = "Cannot allocate crypt request mempool";
		goto bad;
	}

	cc->per_bio_data_size = ti->per_io_data_size =
		ALIGN(sizeof(struct dm_crypt_io) + cc->dmreq_start + additional_req_size,
				ARCH_KMALLOC_MINALIGN);

	printk("per bio data size = %d\n", cc->per_bio_data_size);
	ret = mempool_init(&cc->page_pool, BIO_MAX_VECS, crypt_page_alloc, crypt_page_free, cc);
	if (ret) {
		ti->error = "Cannot allocate page mempool";
		goto bad;
	}

	ret = bioset_init(&cc->bs, MIN_IOS, 0, BIOSET_NEED_BVECS);
	if (ret) {
		ti->error = "Cannot allocate crypt bioset";
		goto bad;
	}

	mutex_init(&cc->bio_alloc_lock);

	ret = -EINVAL;
	if ((sscanf(argv[2], "%llu%c", &tmpll, &dummy) != 1) ||
			(tmpll & ((cc->sector_size >> SECTOR_SHIFT) - 1))) {
		ti->error = "Invalid iv_offset sector";
		goto bad;
	}
	cc->iv_offset = tmpll;

	ret = dm_get_device(ti, argv[3], dm_table_get_mode(ti->table), &cc->dev);
	if (ret) {
		ti->error = "Device lookup failed";
		goto bad;
	}

	printk("dev name is %s", cc->dev->name);
	printk("Disk name is %s\n", cc->dev->bdev->bd_disk->disk_name);

	ret = -EINVAL;
	if (sscanf(argv[4], "%llu%c", &tmpll, &dummy) != 1 || tmpll != (sector_t)tmpll) {
		ti->error = "Invalid device sector";
		goto bad;
	}
	cc->start = tmpll;
	printk("start = %d\n", cc->start);

	if (bdev_is_zoned(cc->dev->bdev)) {
		/*
		 * For zoned block devices, we need to preserve the issuer write
		 * ordering. To do so, disable write workqueues and force inline
		 * encryption completion.
		 */
		set_bit(DM_CRYPT_NO_WRITE_WORKQUEUE, &cc->flags);
		set_bit(DM_CRYPT_WRITE_INLINE, &cc->flags);

		/*
		 * All zone append writes to a zone of a zoned block device will
		 * have the same BIO sector, the start of the zone. When the
		 * cypher IV mode uses sector values, all data targeting a
		 * zone will be encrypted using the first sector numbers of the
		 * zone. This will not result in write errors but will
		 * cause most reads to fail as reads will use the sector values
		 * for the actual data locations, resulting in IV mismatch.
		 * To avoid this problem, ask DM core to emulate zone append
		 * operations with regular writes.
		 */
		DMDEBUG("Zone append operations will be emulated");
		ti->emulate_zone_append = true;
	}

	if (crypt_integrity_aead(cc) || cc->integrity_iv_size) {
		//printk("inside IV check, IV size %d\n", cc->integrity_iv_size);
		ret = crypt_integrity_ctr(cc, ti);
		if (ret)
			goto bad;

		cc->tag_pool_max_sectors = POOL_ENTRY_SIZE / cc->on_disk_tag_size;
		if (!cc->tag_pool_max_sectors)
			cc->tag_pool_max_sectors = 1;

		ret = mempool_init_kmalloc_pool(&cc->tag_pool, MIN_IOS,
				cc->tag_pool_max_sectors * cc->on_disk_tag_size);
		if (ret) {
			ti->error = "Cannot allocate integrity tags mempool";
			goto bad;
		}

		cc->tag_pool_max_sectors <<= cc->sector_shift;
	}

	ret = -ENOMEM;
	cc->io_queue = alloc_workqueue("kcryptd_io/%s", WQ_MEM_RECLAIM, 1, devname);
	if (!cc->io_queue) {
		ti->error = "Couldn't create kcryptd io queue";
		goto bad;
	}

	if (test_bit(DM_CRYPT_SAME_CPU, &cc->flags))
		cc->crypt_queue = alloc_workqueue("kcryptd/%s", WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM,
				1, devname);
	else
		cc->crypt_queue = alloc_workqueue("kcryptd/%s",
				WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM | WQ_UNBOUND,
				num_online_cpus(), devname);
	if (!cc->crypt_queue) {
		ti->error = "Couldn't create kcryptd queue";
		goto bad;
	}

	spin_lock_init(&cc->write_thread_lock);
	cc->write_tree = RB_ROOT;

	cc->write_thread = kthread_run(dmcrypt_write, cc, "dmcrypt_write/%s", devname);
	if (IS_ERR(cc->write_thread)) {
		ret = PTR_ERR(cc->write_thread);
		cc->write_thread = NULL;
		ti->error = "Couldn't spawn write thread";
		goto bad;
	}

	bio_file = file_open("/tmp/bio", O_CREAT|O_WRONLY, 0);

	if (!test_bit(DM_CRYPT_STORE_DATA_IN_INTEGRITY_MD, &cc->flags))
		process_map_data(cc);

	ti->num_flush_bios = 1;
	ti->limit_swap_bios = true;
	ti->accounts_remapped_io = true;

	dm_audit_log_ctr(DM_MSG_PREFIX, ti, 1);
	return 0;

bad:
	dm_audit_log_ctr(DM_MSG_PREFIX, ti, 0);
	crypt_dtr(ti);
	return ret;
}

static int crypt_map(struct dm_target *ti, struct bio *bio)
{
	struct dm_crypt_io *io;
	struct crypt_config *cc = ti->private;

	printk("\nInside crypt_map, %s, Bio address %p, BIO direction %s, total bytes %d, total sectors %d, first sector %d\n",\ 
			(test_bit(DM_CRYPT_STORE_DATA_IN_INTEGRITY_MD, &cc->flags))? "PD Device" : "", bio, \
			(bio_data_dir(bio) == WRITE) ? "WRITE" : "READ", bio->bi_iter.bi_size, bio_sectors(bio), bio->bi_iter.bi_sector);

	/*
	 * If bio is REQ_PREFLUSH or REQ_OP_DISCARD, just bypass crypt queues.
	 * - for REQ_PREFLUSH device-mapper core ensures that no IO is in-flight
	 * - for REQ_OP_DISCARD caller must use flush if IO ordering matters
	 */
	if (unlikely(bio->bi_opf & REQ_PREFLUSH ||
				bio_op(bio) == REQ_OP_DISCARD)) {
		bio_set_dev(bio, cc->dev->bdev);
		if (bio_sectors(bio))
			bio->bi_iter.bi_sector = cc->start +
				dm_target_offset(ti, bio->bi_iter.bi_sector);
		return DM_MAPIO_REMAPPED;
	}

	/*
	 * Check if bio is too large, split as needed.
	 */
	if (unlikely(bio->bi_iter.bi_size > (BIO_MAX_VECS << PAGE_SHIFT)) &&
			(bio_data_dir(bio) == WRITE || cc->on_disk_tag_size))
		dm_accept_partial_bio(bio, ((BIO_MAX_VECS << PAGE_SHIFT) >> SECTOR_SHIFT));

	/*
	 * Ensure that bio is a multiple of internal sector encryption size
	 * and is aligned to this size as defined in IO hints.
	 */
	if (unlikely((bio->bi_iter.bi_sector & ((cc->sector_size >> SECTOR_SHIFT) - 1)) != 0))
		return DM_MAPIO_KILL;

	if (unlikely(bio->bi_iter.bi_size & (cc->sector_size - 1)))
		return DM_MAPIO_KILL;

	io = dm_per_bio_data(bio, cc->per_bio_data_size);
	//printk("dm target offset %d, on_disk_tag_size %d\n", dm_target_offset(ti, bio->bi_iter.bi_sector), cc->on_disk_tag_size);
	crypt_io_init(io, cc, bio, dm_target_offset(ti, bio->bi_iter.bi_sector));

	if (cc->on_disk_tag_size) {
		unsigned tag_len;
		if (test_bit(DM_CRYPT_STORE_DATA_IN_INTEGRITY_MD, &cc->flags)) {
			tag_len = NUM_PUBLIC_SECTORS_PER_HIDDEN_SECTOR * bio_sectors(bio) * cc->on_disk_tag_size;
		}
		else
			tag_len = cc->on_disk_tag_size * (bio_sectors(bio) >> cc->sector_shift);
		printk("crypt_map tag len = %d, bio_sectors %d, sector_shift %d", tag_len, bio_sectors(bio), cc->sector_shift);

		if (unlikely(tag_len > KMALLOC_MAX_SIZE) ||
				unlikely(!(io->integrity_metadata = kmalloc(tag_len,
							GFP_NOIO | __GFP_NORETRY | __GFP_NOMEMALLOC | __GFP_NOWARN)))) {
			if (bio_sectors(bio) > cc->tag_pool_max_sectors)
				dm_accept_partial_bio(bio, cc->tag_pool_max_sectors);
			io->integrity_metadata = mempool_alloc(&cc->tag_pool, GFP_NOIO);
			io->integrity_metadata_from_pool = true;
		}
		memset(io->integrity_metadata, 67, tag_len);
	}


	if (crypt_integrity_aead(cc))
		io->ctx.r.req_aead = (struct aead_request *)(io + 1);
	else
		io->ctx.r.req = (struct skcipher_request *)(io + 1);

	if (bio_data_dir(io->base_bio) == READ) {
		if (kcryptd_io_read(io, CRYPT_MAP_READ_GFP))
			kcryptd_queue_read(io);
	} else
		kcryptd_queue_crypt(io);

	return DM_MAPIO_SUBMITTED;
}

static char hex2asc(unsigned char c)
{
	return c + '0' + ((unsigned)(9 - c) >> 4 & 0x27);
}

static void crypt_status(struct dm_target *ti, status_type_t type,
		unsigned status_flags, char *result, unsigned maxlen)
{
	struct crypt_config *cc = ti->private;
	unsigned i, sz = 0;
	int num_feature_args = 0;

	switch (type) {
		case STATUSTYPE_INFO:
			result[0] = '\0';
			break;

		case STATUSTYPE_TABLE:
			DMEMIT("%s ", cc->cipher_string);

			if (cc->key_size > 0) {
				if (cc->key_string)
					DMEMIT(":%u:%s", cc->key_size, cc->key_string);
				else {
					for (i = 0; i < cc->key_size; i++) {
						DMEMIT("%c%c", hex2asc(cc->key[i] >> 4),
								hex2asc(cc->key[i] & 0xf));
					}
				}
			} else
				DMEMIT("-");

			DMEMIT(" %llu %s %llu", (unsigned long long)cc->iv_offset,
					cc->dev->name, (unsigned long long)cc->start);

			num_feature_args += !!ti->num_discard_bios;
			num_feature_args += test_bit(DM_CRYPT_SAME_CPU, &cc->flags);
			num_feature_args += test_bit(DM_CRYPT_NO_OFFLOAD, &cc->flags);
			num_feature_args += test_bit(DM_CRYPT_NO_READ_WORKQUEUE, &cc->flags);
			num_feature_args += test_bit(DM_CRYPT_NO_WRITE_WORKQUEUE, &cc->flags);
			num_feature_args += cc->sector_size != (1 << SECTOR_SHIFT);
			num_feature_args += test_bit(CRYPT_IV_LARGE_SECTORS, &cc->cipher_flags);
			if (cc->on_disk_tag_size)
				num_feature_args++;
			if (num_feature_args) {
				DMEMIT(" %d", num_feature_args);
				if (ti->num_discard_bios)
					DMEMIT(" allow_discards");
				if (test_bit(DM_CRYPT_SAME_CPU, &cc->flags))
					DMEMIT(" same_cpu_crypt");
				if (test_bit(DM_CRYPT_NO_OFFLOAD, &cc->flags))
					DMEMIT(" submit_from_crypt_cpus");
				if (test_bit(DM_CRYPT_NO_READ_WORKQUEUE, &cc->flags))
					DMEMIT(" no_read_workqueue");
				if (test_bit(DM_CRYPT_NO_WRITE_WORKQUEUE, &cc->flags))
					DMEMIT(" no_write_workqueue");
				if (cc->on_disk_tag_size)
					DMEMIT(" integrity:%u:%s", cc->on_disk_tag_size, cc->cipher_auth);
				if (cc->sector_size != (1 << SECTOR_SHIFT))
					DMEMIT(" sector_size:%d", cc->sector_size);
				if (test_bit(CRYPT_IV_LARGE_SECTORS, &cc->cipher_flags))
					DMEMIT(" iv_large_sectors");
			}
			break;

		case STATUSTYPE_IMA:
			DMEMIT_TARGET_NAME_VERSION(ti->type);
			DMEMIT(",allow_discards=%c", ti->num_discard_bios ? 'y' : 'n');
			DMEMIT(",same_cpu_crypt=%c", test_bit(DM_CRYPT_SAME_CPU, &cc->flags) ? 'y' : 'n');
			DMEMIT(",submit_from_crypt_cpus=%c", test_bit(DM_CRYPT_NO_OFFLOAD, &cc->flags) ?
					'y' : 'n');
			DMEMIT(",no_read_workqueue=%c", test_bit(DM_CRYPT_NO_READ_WORKQUEUE, &cc->flags) ?
					'y' : 'n');
			DMEMIT(",no_write_workqueue=%c", test_bit(DM_CRYPT_NO_WRITE_WORKQUEUE, &cc->flags) ?
					'y' : 'n');
			DMEMIT(",iv_large_sectors=%c", test_bit(CRYPT_IV_LARGE_SECTORS, &cc->cipher_flags) ?
					'y' : 'n');

			if (cc->on_disk_tag_size)
				DMEMIT(",integrity_tag_size=%u,cipher_auth=%s",
						cc->on_disk_tag_size, cc->cipher_auth);
			if (cc->sector_size != (1 << SECTOR_SHIFT))
				DMEMIT(",sector_size=%d", cc->sector_size);
			if (cc->cipher_string)
				DMEMIT(",cipher_string=%s", cc->cipher_string);

			DMEMIT(",key_size=%u", cc->key_size);
			DMEMIT(",key_parts=%u", cc->key_parts);
			DMEMIT(",key_extra_size=%u", cc->key_extra_size);
			DMEMIT(",key_mac_size=%u", cc->key_mac_size);
			DMEMIT(";");
			break;
	}
}

static void crypt_postsuspend(struct dm_target *ti)
{
	struct crypt_config *cc = ti->private;

	set_bit(DM_CRYPT_SUSPENDED, &cc->flags);
}

static int crypt_preresume(struct dm_target *ti)
{
	struct crypt_config *cc = ti->private;

	if (!test_bit(DM_CRYPT_KEY_VALID, &cc->flags)) {
		DMERR("aborting resume - crypt key is not set.");
		return -EAGAIN;
	}

	return 0;
}

static void crypt_resume(struct dm_target *ti)
{
	struct crypt_config *cc = ti->private;

	clear_bit(DM_CRYPT_SUSPENDED, &cc->flags);
}

/* Message interface
 *	key set <key>
 *	key wipe
 */
static int crypt_message(struct dm_target *ti, unsigned argc, char **argv,
		char *result, unsigned maxlen)
{
	struct crypt_config *cc = ti->private;
	int key_size, ret = -EINVAL;

	if (argc < 2)
		goto error;

	if (!strcasecmp(argv[0], "key")) {
		if (!test_bit(DM_CRYPT_SUSPENDED, &cc->flags)) {
			DMWARN("not suspended during key manipulation.");
			return -EINVAL;
		}
		if (argc == 3 && !strcasecmp(argv[1], "set")) {
			/* The key size may not be changed. */
			key_size = get_key_size(&argv[2]);
			if (key_size < 0 || cc->key_size != key_size) {
				memset(argv[2], '0', strlen(argv[2]));
				return -EINVAL;
			}

			ret = crypt_set_key(cc, argv[2]);
			if (ret)
				return ret;
			if (cc->iv_gen_ops && cc->iv_gen_ops->init)
				ret = cc->iv_gen_ops->init(cc);
			/* wipe the kernel key payload copy */
			if (cc->key_string)
				memset(cc->key, 0, cc->key_size * sizeof(u8));
			return ret;
		}
		if (argc == 2 && !strcasecmp(argv[1], "wipe"))
			return crypt_wipe_key(cc);
	}

error:
	DMWARN("unrecognised message received.");
	return -EINVAL;
}

static int crypt_iterate_devices(struct dm_target *ti,
		iterate_devices_callout_fn fn, void *data)
{
	struct crypt_config *cc = ti->private;

	return fn(ti, cc->dev, cc->start, ti->len, data);
}

static void crypt_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct crypt_config *cc = ti->private;

	/*
	 * Unfortunate constraint that is required to avoid the potential
	 * for exceeding underlying device's max_segments limits -- due to
	 * crypt_alloc_buffer() possibly allocating pages for the encryption
	 * bio that are not as physically contiguous as the original bio.
	 */
	limits->max_segment_size = PAGE_SIZE;

	limits->logical_block_size =
		max_t(unsigned, limits->logical_block_size, cc->sector_size);
	limits->physical_block_size =
		max_t(unsigned, limits->physical_block_size, cc->sector_size);
	limits->io_min = max_t(unsigned, limits->io_min, cc->sector_size);
}

static struct target_type crypt_target = {
	.name   = "crypt",
	.version = {1, 24, 0},
	.module = THIS_MODULE,
	.ctr	= crypt_ctr,
	.dtr	= crypt_dtr,
	.features = DM_TARGET_ZONED_HM,
	.report_zones = crypt_report_zones,
	.map	= crypt_map,
	.status = crypt_status,
	.postsuspend = crypt_postsuspend,
	.preresume = crypt_preresume,
	.resume = crypt_resume,
	.message = crypt_message,
	.iterate_devices = crypt_iterate_devices,
	.io_hints = crypt_io_hints,
};

static int __init dm_crypt_init(void)
{
	int r;

	r = dm_register_target(&crypt_target);
	if (r < 0)
		DMERR("register failed %d", r);

	return r;
}

static void __exit dm_crypt_exit(void)
{
	dm_unregister_target(&crypt_target);
}

module_init(dm_crypt_init);
module_exit(dm_crypt_exit);

MODULE_AUTHOR("Jana Saout <jana@saout.de>");
MODULE_DESCRIPTION(DM_NAME " target for transparent encryption / decryption");
MODULE_LICENSE("GPL");
