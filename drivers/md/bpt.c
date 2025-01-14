/*
 *  bpt.c  
 */
#define Version "1.16.1"
/*
 *
 *  bpt:  B+ Tree Implementation
 *
 *  Copyright (c) 2018  Amittai Aviram  http://www.amittai.com
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice, 
 *  this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice, 
 *  this list of conditions and the following disclaimer in the documentation 
 *  and/or other materials provided with the distribution.
 
 *  3. The name of the copyright holder may not be used to endorse
 *  or promote products derived from this software without specific
 *  prior written permission.
 
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE 
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 *  POSSIBILITY OF SUCH DAMAGE.
 
 *  Author:  Amittai Aviram 
 *	http://www.amittai.com
 *	amittai.aviram@gmail.com or afa13@columbia.edu
 *  Original Date:  26 June 2010
 *  Last modified: 02 September 2018
 *
 *  This implementation demonstrates the B+ tree data structure
 *  for educational purposes, includin insertion, deletion, search, and display
 *  of the search path, the leaves, or the whole tree.
 *  
 *  Must be compiled with a C99-compliant C compiler such as the latest GCC.
 *
 *  Usage:  bpt [order]
 *  where order is an optional argument
 *  (integer MIN_ORDER <= order <= MAX_ORDER)
 *  defined as the maximal number of pointers in any node.
 *
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

#include "dm-crypt.h"

#define ZONE_SIZE 10240 //10KB
#define IV_PER_NODE 8
#define NODE_SIZE IV_PER_NODE * 16 //bytes
#define IS_LEAF_OFFSET 92 //bits
#define IS_LEAF_LEN 8 //bits
#define NUM_KEYS_OFFSET IS_LEAF_OFFSET + 8 //bits
#define NUM_KEYS_LEN 8 //bits
#define BITS_PER_ZONE_NUM 14

#define BITS_PER_SECTOR_NUM 32

#define ROOT_MAGIC_POSN 28
#define ROOT_INITIALIZED 0xAA
#define START_OF_ROOT_NODE 0

#define malloc(x) kmalloc(x, GFP_KERNEL)
#define free(x) kfree(x)

// Default order is 16.
#define DEFAULT_ORDER  16 

// Minimum order is necessarily 3.  We set the maximum
// order arbitrarily.  You may change the maximum order.
#define MIN_ORDER 3
#define MAX_ORDER 20

// Constant for optional command-line input with "i" command.
#define BUFFER_SIZE 256

// TYPES.

/* Type representing the record
 * to which a given key refers.
 * In a real B+ tree system, the
 * record would hold data (in a database)
 * or a file (in an operating system)
 * or some other information.
 * Users can rewrite this part of the code
 * to change the type and content
 * of the value field.
 */
typedef struct record {
	int value;
} record;

/* Type representing a node in the B+ tree.
 * This type is general enough to serve for both
 * the leaf and the internal node.
 * The heart of the node is the array
 * of keys and the array of corresponding
 * pointers.  The relation between keys
 * and pointers differs between leaves and
 * internal nodes.  In a leaf, the index
 * of each key equals the index of its corresponding
 * pointer, with a maximum of order - 1 key-pointer
 * pairs.  The last pointer points to the
 * leaf to the right (or NULL in the case
 * of the rightmost leaf).
 * In an internal node, the first pointer
 * refers to lower nodes with keys less than
 * the smallest key in the keys array.  Then,
 * with indices i starting at 0, the pointer
 * at i + 1 points to the subtree with keys
 * greater than or equal to the key in this
 * node at index i.
 * The num_keys field is used to keep
 * track of the number of valid keys.
 * In an internal node, the number of valid
 * pointers is always num_keys + 1.
 * In a leaf, the number of valid pointers
 * to data is always num_keys.  The
 * last leaf pointer points to the next leaf.
 */
typedef struct node {
	void ** pointers;
	bool *pointers_expanded;
	unsigned *pointers_disk;
	int * keys;
	struct node * parent;
	struct node * parent_disk;
	bool is_leaf;
	int num_keys;
	struct node * next; // Used for queue.
} node;


// GLOBALS.

/* The order determines the maximum and minimum
 * number of entries (keys and pointers) in any
 * node.  Every node has at most order - 1 keys and
 * at least (roughly speaking) half that number.
 * Every leaf has as many pointers to data as keys,
 * and every internal node has one more pointer
 * to a subtree than the number of keys.
 * This global variable is initialized to the
 * default value.
 */
int order = DEFAULT_ORDER;

/* The queue is used to print the tree in
 * level order, starting from the root
 * printing each entire rank on a separate
 * line, finishing with the leaves.
 */
node * queue = NULL;

/* The user can toggle on and off the "verbose"
 * property, which causes the pointer addresses
 * to be printed out in hexadecimal notation
 * next to their corresponding keys.
 */
bool verbose_output = false;

node *root = NULL;


// FUNCTION PROTOTYPES.

// Output and utility.

void license_notice(void);
void usage_1(void);
void usage_2(void);
void usage_3(void);
void enqueue(node * new_node);
node * dequeue(void);
int height(node * const root);
int path_to_root(node * const root, node * child);
void print_leaves(node * const root);
void print_tree(node * const root);
void find_and_print(struct dm_crypt_io *io, node * const root, int key, bool verbose); 
void find_and_print_range(struct dm_crypt_io *io, node * const root, int range1, int range2, bool verbose); 
int find_range(struct dm_crypt_io *io,node * const root, int key_start, int key_end, bool verbose,
		int returned_keys[], void * returned_pointers[]); 
node * find_leaf(struct dm_crypt_io *io, node * const root, int key, bool verbose);
record * find(struct dm_crypt_io *io, node * root, int key, bool verbose, node ** leaf_out);
int cut(int length);

// Insertion.

record * make_record(int value);
node * make_node(void);
node * make_leaf(void);
int get_left_index(node * parent, node * left);
node * insert_into_leaf(struct dm_crypt_io *io, node * leaf, int key, record * pointer);
node * insert_into_leaf_after_splitting(struct dm_crypt_io *io, node * root, node * leaf, int key,
										record * pointer);
node * insert_into_node(struct dm_crypt_io *io, node * root, node * parent, 
		int left_index, int key, node * right, unsigned left_disk, unsigned right_disk);
node * insert_into_node_after_splitting(struct dm_crypt_io *io, node * root, node * parent, int left_index,
		int key, node * right, unsigned right_disk);
node * insert_into_parent(struct dm_crypt_io *io,node * root, node * left, int key, node * right, unsigned left_disk, unsigned right_disk);
node * insert_into_new_root(node * left, int key, node * right, unsigned left_disk, unsigned right_disk);
node * start_new_tree(struct dm_crypt_io *io, int key, record * pointer);
node * insert(struct dm_crypt_io *io, node * root, int key, int value);

// Deletion.

int get_neighbor_index(node * n);
node * adjust_root(node * root);
node * coalesce_nodes(struct dm_crypt_io *io, node * root, node * n, node * neighbor,
					  int neighbor_index, int k_prime);
node * redistribute_nodes(node * root, node * n, node * neighbor,
						  int neighbor_index,
		int k_prime_index, int k_prime);
node * delete_entry(struct dm_crypt_io *io, node * root, node * n, int key, void * pointer);
node * delete(struct dm_crypt_io *io, node * root, int key);

unsigned initialize_disknode_from_node(struct dm_crypt_io *io, node *node, bool is_root);
void initialize_node_from_disknode(struct dm_crypt_io *io, int sector, node *node, unsigned char *data);
// FUNCTION DEFINITIONS.

// OUTPUT AND UTILITIES
static void map_endio(struct bio *clone)
{
        struct dm_crypt_io *io = clone->bi_private;
        struct crypt_config *cc = io->cc;
        unsigned rw = bio_data_dir(clone);

        //printk("Inside map_endio IO address %p, IO flags %d, size= %d, starting sector = %d, direction %s\n",
        //               io, io->flags, clone->bi_iter.bi_size, clone->bi_iter.bi_sector, (rw == WRITE) ? "WRITE" : "READ");
	complete(&io->map_complete);
}
// TODO: Error handling
static int rdwr_sector_metadata(struct dm_crypt_io *io, int op, sector_t sector, unsigned char *data, unsigned size)
{
	int ret = 0; 
	int r;
	struct crypt_config *cc = io->cc;
	printk("rdwr_sector_metadata, %s, sector %d, size %d\n", (op == REQ_OP_WRITE) ? "WRITE" : "READ", sector, size);
	if( op == REQ_OP_WRITE) {
		//first do a read of the required sectors data
                int tag_offset = 0;
                unsigned len = (size / cc->on_disk_tag_size) * cc->sector_size;
                struct bio *bio = crypt_alloc_buffer(io, len, 0);
                bio->bi_private = io;
                bio->bi_end_io = map_endio;
                bio->bi_opf = REQ_OP_READ | REQ_INTEGRITY;
                bio->bi_iter.bi_sector = sector;
                crypt_inc_pending(io);
                dm_submit_bio_remap(io->base_bio, bio);
                wait_for_completion(&io->map_complete);
                reinit_completion(&io->map_complete);

		// decrypt the data read
		crypt_convert_init(cc, &io->ctx, bio, bio, sector, &tag_offset);
		r = crypt_convert(cc, &io->ctx, false, true);

		// encrypt the hidden input data
		struct bio *hbio = crypt_alloc_buffer(io, size, 0);
		hbio->bi_opf = REQ_OP_WRITE;
		struct bvec_iter iter_out = hbio->bi_iter;
		unsigned offset = 0;
		while (iter_out.bi_size) {
			struct bio_vec bv_out = bio_iter_iovec(hbio, iter_out);
			char *buffer = page_to_virt(bv_out.bv_page);

			memcpy(buffer + bv_out.bv_offset, data + offset, size);
			bio_advance_iter(hbio, &iter_out, size);
			offset += size;
		}

		io->flags |= PD_HIDDEN_OPERATION;
		crypt_convert_init(cc, &io->ctx, hbio, hbio, sector, &tag_offset);
		r = crypt_convert(cc, &io->ctx, false, true);

		io->flags &= ~PD_HIDDEN_OPERATION;

		// copy encrypted input data to integrity metadata
		iter_out = hbio->bi_iter;
		offset = 0;
		while (iter_out.bi_size) {
			struct bio_vec bv_out = bio_iter_iovec(hbio, iter_out);
			char *buffer = page_to_virt(bv_out.bv_page);

			memcpy(io->integrity_metadata + offset, buffer + bv_out.bv_offset, size);
			bio_advance_iter(hbio, &iter_out, size);
			offset += size;
		}
		// encrypt and write the whole thing. TODO check if crypt_convert takes IV from integrity_metadata here.
		io->flags |= PD_READ_DURING_HIDDEN_WRITE;
		tag_offset = 0;
                iter_out = bio->bi_iter;
                bio_reset(bio, cc->dev->bdev, REQ_OP_WRITE|REQ_INTEGRITY);
                bio->bi_iter = iter_out;
                bio->bi_private = io;
                bio->bi_end_io = map_endio;
                /* Allocate space for integrity tags */
                if (dm_crypt_integrity_io_alloc(io, bio, 0)) {
                         printk("rdrw_sector dm_crypt_integrity_io_alloc failed!\n");
                         //TODO: handle this gracefully
                }

		crypt_convert_init(cc, &io->ctx, bio, bio, sector, &tag_offset);
		r = crypt_convert(cc, &io->ctx, false, true);
		io->flags &= ~PD_READ_DURING_HIDDEN_WRITE;
                bio->bi_opf = REQ_OP_WRITE | REQ_INTEGRITY;
                dm_submit_bio_remap(io->base_bio, bio);
                wait_for_completion(&io->map_complete);
                reinit_completion(&io->map_complete);

		crypt_free_buffer_pages(cc, bio);
		bio_put(bio);
		crypt_free_buffer_pages(cc, hbio);
		bio_put(hbio);
		crypt_dec_pending(io);
	}
	if( op == REQ_OP_READ) {
		// Read equivalent data sectors along with integrity metadata
		int tag_offset = 0;
		unsigned len = (size / cc->on_disk_tag_size) * cc->sector_size;
		struct bio *bio = crypt_alloc_buffer(io, len, 0);
	        bio->bi_private = io;
		bio->bi_end_io = map_endio;
		bio->bi_opf = REQ_OP_READ | REQ_INTEGRITY;
		bio->bi_iter.bi_sector = sector;
		crypt_inc_pending(io);
		dm_submit_bio_remap(io->base_bio, bio);
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
		io->flags |= PD_HIDDEN_OPERATION;
		crypt_convert_init(cc, &io->ctx, hbio, hbio, sector, &tag_offset);
		r = crypt_convert(cc, &io->ctx, false, true);

		io->flags &= ~PD_HIDDEN_OPERATION;
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
	}
	return ret; 
}

/* Copyright and license notice to user at startup. 
 */
void license_notice(void) {
	printk("bpt version %s -- Copyright (c) 2018  Amittai Aviram "
			"http://www.amittai.com\n", Version);
	printk("This program comes with ABSOLUTELY NO WARRANTY.\n"
			"This is free software, and you are welcome to redistribute it\n"
			"under certain conditions.\n"
			"Please see the headnote in the source code for details.\n");
}


/* First message to the user.
 */
void usage_1(void) {
	printk("B+ Tree of Order %d.\n", order);
	printk("Following Silberschatz, Korth, Sidarshan, Database Concepts, "
		   "5th ed.\n\n"
		   "To build a B+ tree of a different order, start again and enter "
		   "the order\n"
		   "as an integer argument:  bpt <order>  ");
	printk("(%d <= order <= %d).\n", MIN_ORDER, MAX_ORDER);
	printk("To start with input from a file of newline-delimited integers, \n"
		   "start again and enter the order followed by the filename:\n"
		   "bpt <order> <inputfile> .\n");
}


/* Second message to the user.
 */
void usage_2(void) {
	printk("Enter any of the following commands after the prompt > :\n"
	"\ti <k>  -- Insert <k> (an integer) as both key and value).\n"
	"\ti <k> <v> -- Insert the value <v> (an integer) as the value of key <k> (an integer).\n"
	"\tf <k>  -- Find the value under key <k>.\n"
	"\tp <k> -- Print the path from the root to key k and its associated "
		   "value.\n"
	"\tr <k1> <k2> -- Print the keys and values found in the range "
			"[<k1>, <k2>\n"
	"\td <k>  -- Delete key <k> and its associated value.\n"
	"\tx -- Destroy the whole tree.  Start again with an empty tree of the "
		   "same order.\n"
	"\tt -- Print the B+ tree.\n"
	"\tl -- Print the keys of the leaves (bottom row of the tree).\n"
	"\tv -- Toggle output of pointer addresses (\"verbose\") in tree and "
		   "leaves.\n"
	"\tq -- Quit. (Or use Ctl-D or Ctl-C.)\n"
	"\t? -- Print this help message.\n");
}


/* Brief usage note.
 */
void usage_3(void) {
	printk("Usage: ./bpt [<order>]\n");
	printk("\twhere %d <= order <= %d .\n", MIN_ORDER, MAX_ORDER);
}


/* Helper function for printing the
 * tree out.  See print_tree.
 */
void enqueue(node * new_node) {
	node * c;
	if (queue == NULL) {
		queue = new_node;
		queue->next = NULL;
	}
	else {
		c = queue;
		while(c->next != NULL) {
			c = c->next;
		}
		c->next = new_node;
		new_node->next = NULL;
	}
}


/* Helper function for printing the
 * tree out.  See print_tree.
 */
node * dequeue(void) {
	node * n = queue;
	queue = queue->next;
	n->next = NULL;
	return n;
}


/* Prints the bottom row of keys
 * of the tree (with their respective
 * pointers, if the verbose_output flag is set.
 */
void print_leaves(node * const root) {
	if (root == NULL) {
		printk("Empty tree.\n");
		return;
	}
	int i;
	node * c = root;
	while (!c->is_leaf)
		c = c->pointers[0];
	while (true) {
		for (i = 0; i < c->num_keys; i++) {
			if (verbose_output)
				printk("%p ", c->pointers[i]);
			printk("%d ", c->keys[i]);
		}
		if (verbose_output)
			printk("%p ", c->pointers[order - 1]);
		if (c->pointers[order - 1] != NULL) {
			printk(" | ");
			c = c->pointers[order - 1];
		}
		else
			break;
	}
	printk("\n");
}


/* Utility function to give the height
 * of the tree, which length in number of edges
 * of the path from the root to any leaf.
 */
int height(node * const root) {
	int h = 0;
	node * c = root;
	while (!c->is_leaf) {
		c = c->pointers[0];
		h++;
	}
	return h;
}


/* Utility function to give the length in edges
 * of the path from any node to the root.
 */
int path_to_root(node * const root, node * child) {
	int length = 0;
	node * c = child;
	while (c != root) {
		c = c->parent;
		length++;
	}
	return length;
}


/* Prints the B+ tree in the command
 * line in level (rank) order, with the 
 * keys in each node and the '|' symbol
 * to separate nodes.
 * With the verbose_output flag set.
 * the values of the pointers corresponding
 * to the keys also appear next to their respective
 * keys, in hexadecimal notation.
 */
void print_tree(node * const root) {

	node * n = NULL;
	int i = 0;
	int rank = 0;
	int new_rank = 0;

	if (root == NULL) {
		printk("Empty tree.\n");
		return;
	}
	queue = NULL;
	enqueue(root);
	while(queue != NULL) {
		n = dequeue();
		if (n->parent != NULL && n == n->parent->pointers[0]) {
			new_rank = path_to_root(root, n);
			if (new_rank != rank) {
				rank = new_rank;
				printk("\n");
			}
		}
		if (verbose_output) 
			printk("(%p)", n);
		for (i = 0; i < n->num_keys; i++) {
			if (verbose_output)
				printk("%p ", n->pointers[i]);
			printk("%d ", n->keys[i]);
		}
		if (!n->is_leaf)
			for (i = 0; i <= n->num_keys; i++)
				enqueue(n->pointers[i]);
		if (verbose_output) {
			if (n->is_leaf) 
				printk("%p ", n->pointers[order - 1]);
			else
				printk("%p ", n->pointers[n->num_keys]);
		}
		printk("| ");
	}
	printk("\n");
}


/* Finds the record under a given key and prints an
 * appropriate message to stdout.
 */
void find_and_print(struct dm_crypt_io *io, node * const root, int key, bool verbose) {
	node * leaf = NULL;
	record * r = find(io, root, key, verbose, NULL);
	if (r == NULL)
		printk("Record not found under key %d.\n", key);
	else 
		printk("Record at %p -- key %d, value %d.\n",
				r, key, r->value);
}


/* Finds and prints the keys, pointers, and values within a range
 * of keys between key_start and key_end, including both bounds.
 */
void find_and_print_range(struct dm_crypt_io *io, node * const root, int key_start, int key_end,
		bool verbose) {
	int i;
	int array_size = key_end - key_start + 1;
	int returned_keys[array_size];
	void * returned_pointers[array_size];
	int num_found = find_range(io, root, key_start, key_end, verbose,
			returned_keys, returned_pointers);
	if (!num_found)
		printk("None found.\n");
	else {
		for (i = 0; i < num_found; i++)
			printk("Key: %d   Location: %p  Value: %d\n",
					returned_keys[i],
					returned_pointers[i],
					((record *)
					 returned_pointers[i])->value);
	}
}


/* Finds keys and their pointers, if present, in the range specified
 * by key_start and key_end, inclusive.  Places these in the arrays
 * returned_keys and returned_pointers, and returns the number of
 * entries found.
 */
int find_range(struct dm_crypt_io *io, node * const root, int key_start, int key_end, bool verbose,
		int returned_keys[], void * returned_pointers[]) {
	int i, num_found;
	num_found = 0;
	node * n = find_leaf(io, root, key_start, verbose);
	if (n == NULL) return 0;
	for (i = 0; i < n->num_keys && n->keys[i] < key_start; i++) ;
	if (i == n->num_keys) return 0;
	while (n != NULL) {
		for (; i < n->num_keys && n->keys[i] <= key_end; i++) {
			returned_keys[num_found] = n->keys[i];
			returned_pointers[num_found] = n->pointers[i];
			num_found++;
		}
		n = n->pointers[order - 1];
		i = 0;
	}
	return num_found;
}


/* Traces the path from the root to a leaf, searching
 * by key.  Displays information about the path
 * if the verbose flag is set.
 * Returns the leaf containing the given key.
 */
node * find_leaf(struct dm_crypt_io *io, node * const root, int key, bool verbose) {
	int i = 0;
	if (root == NULL) {
		return root;
	}
	node * c = root;
	while (!c->is_leaf) {
		i = 0;
		while (i < c->num_keys) {
			if (key >= c->keys[i]) i++;
			else break;
		}
		if (c->pointers_expanded[i])
			c = (node *)c->pointers[i];
		else {
			node *n = make_node();
			initialize_node_from_disknode(io, c->pointers_disk[i], n, NULL);
			c->pointers[i] = n;
			c->pointers_expanded[i] = true;
			c = n;
		}
	}
	return c;
}


/* Finds and returns the record to which
 * a key refers.
 */
record * find(struct dm_crypt_io *io, node * root, int key, bool verbose, node ** leaf_out) {
	if (root == NULL) {
		if (leaf_out != NULL) {
			*leaf_out = NULL;
		}
		return NULL;
	}

	int i = 0;
	node * leaf = NULL;

	leaf = find_leaf(io, root, key, verbose);

	/* If root != NULL, leaf must have a value, even
	 * if it does not contain the desired key.
	 * (The leaf holds the range of keys that would
	 * include the desired key.) 
	 */

	for (i = 0; i < leaf->num_keys; i++)
		if (leaf->keys[i] == key) break;
	if (leaf_out != NULL) {
		*leaf_out = leaf;
	}
	if (i == leaf->num_keys)
		return NULL;
	else
		return (record *)leaf->pointers[i];
}

unsigned find_value(struct dm_crypt_io *io, node * root, int key, bool verbose, node ** leaf_out) {
        if (root == NULL) {
                if (leaf_out != NULL) {
                        *leaf_out = NULL;
                }
                return -1;
        }

        int i = 0;
        node * leaf = NULL;

        leaf = find_leaf(io, root, key, verbose);

        /* If root != NULL, leaf must have a value, even
         * if it does not contain the desired key.
         * (The leaf holds the range of keys that would
         * include the desired key.)
         */

        for (i = 0; i < leaf->num_keys; i++)
                if (leaf->keys[i] == key) break;
        if (leaf_out != NULL) {
                *leaf_out = leaf;
        }
        if (i == leaf->num_keys)
                return -1;
        else
                return leaf->pointers_disk[i];
}


record * find_update(struct dm_crypt_io *io, node * root, int key, bool verbose, node ** leaf_out, int value) {
        if (root == NULL) {
                if (leaf_out != NULL) {
                        *leaf_out = NULL;
                }
                return NULL;
        }

        int i = 0;
        node * leaf = NULL;

        leaf = find_leaf(io, root, key, verbose);

        /* If root != NULL, leaf must have a value, even
         * if it does not contain the desired key.
         * (The leaf holds the range of keys that would
         * include the desired key.)
         */

        for (i = 0; i < leaf->num_keys; i++)
                if (leaf->keys[i] == key) break;
        if (leaf_out != NULL) {
                *leaf_out = leaf;
        }
        if (i == leaf->num_keys)
                return NULL;
        else {
		leaf->pointers_disk[i] = value;
                return (record *)leaf->pointers[i];
	}
}


/* Finds the appropriate place to
 * split a node that is too big into two.
 */
int cut(int length) {
	if (length % 2 == 0)
		return length/2;
	else
		return length/2 + 1;
}


// INSERTION

/* Creates a new record to hold the value
 * to which a key refers.
 */
record * make_record(int value) {
	record * new_record = (record *)malloc(sizeof(record));
	if (new_record == NULL) {
		printk("Record creation.");
	}
	else {
		new_record->value = value;
	}
	return new_record;
}


/* Creates a new general node, which can be adapted
 * to serve as either a leaf or an internal node.
 */
node * make_node(void) {
	node * new_node;
	int i;
	new_node = malloc(sizeof(node));
	if (new_node == NULL) {
		printk("Node creation.");
	}
	new_node->keys = malloc((order - 1) * sizeof(int));
	if (new_node->keys == NULL) {
		printk("New node keys array.");
	}
	new_node->pointers = malloc(order * sizeof(void *));
	if (new_node->pointers == NULL) {
		printk("New node pointers array.");
	}
        new_node->pointers_expanded = malloc(order * sizeof(bool));
        if (new_node->pointers_expanded == NULL) {
                printk("New node pointers_expanded array.");
        }
        new_node->pointers_disk = malloc(order * sizeof(unsigned));
        if (new_node->pointers_expanded == NULL) {
                printk("New node pointers_disk array.");
        }
	for(i = 0; i < order; i++)
		new_node->pointers_expanded[i] = false;
	new_node->is_leaf = false;
	new_node->num_keys = 0;
	new_node->parent = NULL;
	new_node->next = NULL;
	return new_node;
}

/* Creates a new leaf by creating a node
 * and then adapting it appropriately.
 */
node * make_leaf(void) {
	node * leaf = make_node();
	leaf->is_leaf = true;
	return leaf;
}


/* Helper function used in insert_into_parent
 * to find the index of the parent's pointer to 
 * the node to the left of the key to be inserted.
 */
int get_left_index(node * parent, node * left) {

	int left_index = 0;
	while (left_index <= parent->num_keys && 
			parent->pointers[left_index] != left)
		left_index++;
	return left_index;
}

/* Inserts a new pointer to a record and its corresponding
 * key into a leaf.
 * Returns the altered leaf.
 */
node * insert_into_leaf(struct dm_crypt_io *io, node * leaf, int key, record * pointer) {

	int i, insertion_point;

	insertion_point = 0;
	while (insertion_point < leaf->num_keys && leaf->keys[insertion_point] < key)
		insertion_point++;

	for (i = leaf->num_keys; i > insertion_point; i--) {
		leaf->keys[i] = leaf->keys[i - 1];
		leaf->pointers[i] = leaf->pointers[i - 1];
		leaf->pointers_disk[i] = leaf->pointers_disk[i - 1];
	}
	leaf->keys[insertion_point] = key;
	leaf->pointers[insertion_point] = pointer;
	leaf->pointers_disk[insertion_point] = pointer->value;
	leaf->num_keys++;
	return leaf;
}


/* Inserts a new key and pointer
 * to a new record into a leaf so as to exceed
 * the tree's order, causing the leaf to be split
 * in half.
 */
node * insert_into_leaf_after_splitting(struct dm_crypt_io *io, node * root, node * leaf, int key, record * pointer) {

	node * new_leaf, *lroot;
	int * temp_keys;
	void ** temp_pointers;
	unsigned * temp_pointers_disk;
	int insertion_index, split, new_key, i, j;
	unsigned new_leaf_disk, leaf_disk;

	printk("Inside insert_into_leaf_after_splitting key %d, value %d", key, pointer->value);

	new_leaf = make_leaf();

	temp_keys = malloc(order * sizeof(int));
	if (temp_keys == NULL) {
		printk("Temporary keys array.");
	}

	temp_pointers = malloc(order * sizeof(void *));
	if (temp_pointers == NULL) {
		printk("Temporary pointers array.");
	}

	temp_pointers_disk = malloc(order * sizeof(unsigned));
	if (temp_pointers == NULL) {
		printk("Temporary pointers_disk array.");
	}

	insertion_index = 0;
	while (insertion_index < order - 1 && leaf->keys[insertion_index] < key)
		insertion_index++;

	for (i = 0, j = 0; i < leaf->num_keys; i++, j++) {
		if (j == insertion_index) j++;
		temp_keys[j] = leaf->keys[i];
		temp_pointers[j] = leaf->pointers[i];
		temp_pointers_disk[j] = leaf->pointers_disk[i];
	}

	temp_keys[insertion_index] = key;
	temp_pointers[insertion_index] = pointer;
	temp_pointers_disk[insertion_index] = pointer->value;

	leaf->num_keys = 0;

	split = cut(order - 1);

	for (i = 0; i < split; i++) {
		leaf->pointers[i] = temp_pointers[i];
		leaf->pointers_disk[i] = temp_pointers_disk[i];
		leaf->keys[i] = temp_keys[i];
		leaf->num_keys++;
	}

	for (i = split, j = 0; i < order; i++, j++) {
		new_leaf->pointers[j] = temp_pointers[i];
		new_leaf->pointers_disk[j] = temp_pointers_disk[i];
		new_leaf->keys[j] = temp_keys[i];
		new_leaf->num_keys++;
	}

	free(temp_pointers);
	free(temp_pointers_disk);
	free(temp_keys);

	//last pointer points to the next leaf
	new_leaf->pointers[order - 1] = leaf->pointers[order - 1];
	new_leaf->pointers_disk[order - 1] = leaf->pointers_disk[order - 1];
	leaf->pointers[order - 1] = new_leaf;

	for (i = leaf->num_keys; i < order - 1; i++)
		leaf->pointers[i] = NULL;
	for (i = new_leaf->num_keys; i < order - 1; i++)
		new_leaf->pointers[i] = NULL;

	new_leaf->parent = leaf->parent;
	new_key = new_leaf->keys[0];

	leaf_disk = initialize_disknode_from_node(io, leaf, false);
	new_leaf_disk = initialize_disknode_from_node(io, new_leaf, false);
	leaf->pointers_disk[order - 1] = new_leaf_disk;
	lroot = insert_into_parent(io, root, leaf, new_key, new_leaf, leaf_disk, new_leaf_disk);
	if (lroot != root) {
		//there's a new root
		initialize_disknode_from_node(io, lroot, true);
		return lroot;
	}
	return root;
}


/* Inserts a new key and pointer to a node
 * into a node into which these can fit
 * without violating the B+ tree properties.
 */
node * insert_into_node(struct dm_crypt_io *io, node * root, node * n, 
		int left_index, int key, node * right, unsigned left_disk, unsigned right_disk) {
	int i;

	for (i = n->num_keys; i > left_index; i--) {
		n->pointers[i + 1] = n->pointers[i];
		n->pointers_disk[i + 1] = n->pointers_disk[i];
		n->keys[i] = n->keys[i - 1];
	}
	n->pointers[left_index + 1] = right;
	n->pointers_disk[left_index + 1] = right_disk;
	n->keys[left_index] = key;
	n->num_keys++;
	initialize_disknode_from_node(io, n, false);
	return root;
}


/* Inserts a new key and pointer to a node
 * into a node, causing the node's size to exceed
 * the order, and causing the node to split into two.
 */
node * insert_into_node_after_splitting(struct dm_crypt_io *io, node * root, node * old_node, int left_index, 
		int key, node * right, unsigned right_disk) {

	int i, j, split, k_prime;
	node * new_node, * child;
	int * temp_keys;
	node ** temp_pointers;
	unsigned * temp_pointers_disk;
	unsigned old_disk, new_disk;

	printk("Inside insert_into_node_after_splitting, key %d, right_disk %d", key, right_disk);

	/* First create a temporary set of keys and pointers
	 * to hold everything in order, including
	 * the new key and pointer, inserted in their
	 * correct places. 
	 * Then create a new node and copy half of the 
	 * keys and pointers to the old node and
	 * the other half to the new.
	 */

	temp_pointers = malloc((order + 1) * sizeof(node *));
	if (temp_pointers == NULL) {
		printk("Temporary pointers array for splitting nodes.");
	}
        temp_pointers_disk = malloc((order + 1) * sizeof(unsigned));
        if (temp_pointers == NULL) {
                printk("Temporary pointers array for splitting nodes.");
        }
	temp_keys = malloc(order * sizeof(int));
	if (temp_keys == NULL) {
		printk("Temporary keys array for splitting nodes.");
	}

	for (i = 0, j = 0; i < old_node->num_keys + 1; i++, j++) {
		if (j == left_index + 1) j++;
		temp_pointers[j] = old_node->pointers[i];
		temp_pointers_disk[j] = old_node->pointers_disk[i];
	}

	for (i = 0, j = 0; i < old_node->num_keys; i++, j++) {
		if (j == left_index) j++;
		temp_keys[j] = old_node->keys[i];
	}

	temp_pointers[left_index + 1] = right;
	temp_pointers_disk[left_index + 1] = right_disk;
	temp_keys[left_index] = key;

	/* Create the new node and copy
	 * half the keys and pointers to the
	 * old and half to the new.
	 */  
	split = cut(order);
	new_node = make_node();
	old_node->num_keys = 0;
	for (i = 0; i < split - 1; i++) {
		old_node->pointers[i] = temp_pointers[i];
		old_node->pointers_disk[i] = temp_pointers_disk[i];
		old_node->keys[i] = temp_keys[i];
		old_node->num_keys++;
	}
	old_node->pointers[i] = temp_pointers[i];
	k_prime = temp_keys[split - 1];
	for (++i, j = 0; i < order; i++, j++) {
		new_node->pointers[j] = temp_pointers[i];
		new_node->pointers_disk[j] = temp_pointers_disk[i];
		new_node->keys[j] = temp_keys[i];
		new_node->num_keys++;
	}
	new_node->pointers[j] = temp_pointers[i];
	free(temp_pointers);
	free(temp_pointers_disk);
	free(temp_keys);
	new_node->parent = old_node->parent;
	new_node->parent_disk = old_node->parent_disk;
	for (i = 0; i <= new_node->num_keys; i++) {
		child = new_node->pointers[i];
		child->parent = new_node;
	}

	/* Insert a new key into the parent of the two
	 * nodes resulting from the split, with
	 * the old node to the left and the new to the right.
	 */

        old_disk = initialize_disknode_from_node(io, old_node, false);
        new_disk = initialize_disknode_from_node(io, new_node, false);

	return insert_into_parent(io, root, old_node, k_prime, new_node, old_disk, new_disk);
}



/* Inserts a new node (leaf or internal node) into the B+ tree.
 * Returns the root of the tree after insertion.
 */
node * insert_into_parent(struct dm_crypt_io *io, node * root, node * left, int key, node * right, unsigned left_disk, unsigned right_disk) {

	int left_index;
	node * parent;

	parent = left->parent;

	/* Case: new root. */

	if (parent == NULL)
		return insert_into_new_root(left, key, right, left_disk, right_disk);

	/* Case: leaf or node. (Remainder of
	 * function body.)  
	 */

	/* Find the parent's pointer to the left 
	 * node.
	 */

	left_index = get_left_index(parent, left);


	/* Simple case: the new key fits into the node. 
	 */

	if (parent->num_keys < order - 1)
		return insert_into_node(io, root, parent, left_index, key, right, left_disk, right_disk);

	/* Harder case:  split a node in order 
	 * to preserve the B+ tree properties.
	 */

	return insert_into_node_after_splitting(io, root, parent, left_index, key, right, right_disk);
}


/* Creates a new root for two subtrees
 * and inserts the appropriate key into
 * the new root.
 */
node * insert_into_new_root(node * left, int key, node * right, unsigned left_disk, unsigned right_disk) {

	node * root = make_node();
	root->keys[0] = key;
	root->pointers[0] = left;
	root->pointers_disk[0] = left_disk;
	root->pointers_expanded[0] = true;
	root->pointers[1] = right;
	root->pointers_disk[1] = right_disk;
	root->pointers_expanded[1] = true;
	root->num_keys++;
	root->parent = NULL;
	left->parent = root;
	right->parent = root;
	return root;
}



/* First insertion:
 * start a new tree.
 */
node * start_new_tree(struct dm_crypt_io *io, int key, record * pointer) {

	node * root = make_leaf();
	root->keys[0] = key;
	root->pointers[0] = pointer;
	root->pointers_disk[0] = pointer->value;
	root->pointers[order - 1] = NULL;
	root->parent = NULL;
	root->num_keys++;
	printk("Starting a new tree with key %d, pointer %d", key, pointer->value);
	initialize_disknode_from_node(io, root, true);
	return root;
}



/* Master insertion function.
 * Inserts a key and an associated value into
 * the B+ tree, causing the tree to be adjusted
 * however necessary to maintain the B+ tree
 * properties.
 */
node * insert(struct dm_crypt_io *io, node * root, int key, int value) {

	record * record_pointer = NULL;
	node * leaf = NULL;
	node * key_leaf = NULL;

	/* The current implementation ignores
	 * duplicates.
	 */
	printk("Inside insert, root %p, key %d, value %d", root, key, value);

	record_pointer = find_update(io, root, key, false, &key_leaf, value);
	if (record_pointer != NULL) {

		/* If the key already exists in this tree, update
		 * the value and return the tree.
		 */
		printk("Key %d already in map. Refreshing it", key);
		record_pointer->value = value;
		initialize_disknode_from_node(io, key_leaf, key_leaf == root);
		return root;
	}

	/* Create a new record for the
	 * value.
	 */
	record_pointer = make_record(value);


	/* Case: the tree does not exist yet.
	 * Start a new tree.
	 */

	if (root == NULL) 
		return start_new_tree(io, key, record_pointer);


	/* Case: the tree already exists.
	 * (Rest of function body.)
	 */

	leaf = find_leaf(io, root, key, false);

	/* Case: leaf has room for key and record_pointer.
	 */

	if (leaf->num_keys < order - 1) {
		leaf = insert_into_leaf(io, leaf, key, record_pointer);
		initialize_disknode_from_node(io, leaf, leaf == root);
		return root;
	}


	/* Case:  leaf must be split.
	 */

	return insert_into_leaf_after_splitting(io, root, leaf, key, record_pointer);
}




// DELETION.

/* Utility function for deletion.  Retrieves
 * the index of a node's nearest neighbor (sibling)
 * to the left if one exists.  If not (the node
 * is the leftmost child), returns -1 to signify
 * this special case.
 */
int get_neighbor_index(node * n) {

	int i;

	/* Return the index of the key to the left
	 * of the pointer in the parent pointing
	 * to n.  
	 * If n is the leftmost child, this means
	 * return -1.
	 */
	for (i = 0; i <= n->parent->num_keys; i++)
		if (n->parent->pointers[i] == n)
			return i - 1;

	// Error state.
	printk("Search for nonexistent pointer to node in parent.\n");
	printk("Node:  %#lx\n", (unsigned long)n);

	return 9999;
}


node * remove_entry_from_node(node * n, int key, node * pointer) {

	int i, num_pointers;

	// Remove the key and shift other keys accordingly.
	i = 0;
	while (n->keys[i] != key)
		i++;
	for (++i; i < n->num_keys; i++)
		n->keys[i - 1] = n->keys[i];

	// Remove the pointer and shift other pointers accordingly.
	// First determine number of pointers.
	num_pointers = n->is_leaf ? n->num_keys : n->num_keys + 1;
	i = 0;
	while (n->pointers[i] != pointer)
		i++;
	for (++i; i < num_pointers; i++)
		n->pointers[i - 1] = n->pointers[i];


	// One key fewer.
	n->num_keys--;

	// Set the other pointers to NULL for tidiness.
	// A leaf uses the last pointer to point to the next leaf.
	if (n->is_leaf)
		for (i = n->num_keys; i < order - 1; i++)
			n->pointers[i] = NULL;
	else
		for (i = n->num_keys + 1; i < order; i++)
			n->pointers[i] = NULL;

	return n;
}


node * adjust_root(node * root) {

	node * new_root;

	/* Case: nonempty root.
	 * Key and pointer have already been deleted,
	 * so nothing to be done.
	 */

	if (root->num_keys > 0)
		return root;

	/* Case: empty root. 
	 */

	// If it has a child, promote 
	// the first (only) child
	// as the new root.

	if (!root->is_leaf) {
		new_root = root->pointers[0];
		new_root->parent = NULL;
	}

	// If it is a leaf (has no children),
	// then the whole tree is empty.

	else
		new_root = NULL;

	free(root->keys);
	free(root->pointers);
	free(root);

	return new_root;
}


/* Coalesces a node that has become
 * too small after deletion
 * with a neighboring node that
 * can accept the additional entries
 * without exceeding the maximum.
 */
node * coalesce_nodes(struct dm_crypt_io *io, node * root, node * n, node * neighbor, int neighbor_index, int k_prime) {

	int i, j, neighbor_insertion_index, n_end;
	node * tmp;

	/* Swap neighbor with node if node is on the
	 * extreme left and neighbor is to its right.
	 */

	if (neighbor_index == -1) {
		tmp = n;
		n = neighbor;
		neighbor = tmp;
	}

	/* Starting point in the neighbor for copying
	 * keys and pointers from n.
	 * Recall that n and neighbor have swapped places
	 * in the special case of n being a leftmost child.
	 */

	neighbor_insertion_index = neighbor->num_keys;

	/* Case:  nonleaf node.
	 * Append k_prime and the following pointer.
	 * Append all pointers and keys from the neighbor.
	 */

	if (!n->is_leaf) {

		/* Append k_prime.
		 */

		neighbor->keys[neighbor_insertion_index] = k_prime;
		neighbor->num_keys++;


		n_end = n->num_keys;

		for (i = neighbor_insertion_index + 1, j = 0; j < n_end; i++, j++) {
			neighbor->keys[i] = n->keys[j];
			neighbor->pointers[i] = n->pointers[j];
			neighbor->num_keys++;
			n->num_keys--;
		}

		/* The number of pointers is always
		 * one more than the number of keys.
		 */

		neighbor->pointers[i] = n->pointers[j];

		/* All children must now point up to the same parent.
		 */

		for (i = 0; i < neighbor->num_keys + 1; i++) {
			tmp = (node *)neighbor->pointers[i];
			tmp->parent = neighbor;
		}
	}

	/* In a leaf, append the keys and pointers of
	 * n to the neighbor.
	 * Set the neighbor's last pointer to point to
	 * what had been n's right neighbor.
	 */

	else {
		for (i = neighbor_insertion_index, j = 0; j < n->num_keys; i++, j++) {
			neighbor->keys[i] = n->keys[j];
			neighbor->pointers[i] = n->pointers[j];
			neighbor->num_keys++;
		}
		neighbor->pointers[order - 1] = n->pointers[order - 1];
	}

	root = delete_entry(io, root, n->parent, k_prime, n);
	free(n->keys);
	free(n->pointers);
	free(n); 
	return root;
}


/* Redistributes entries between two nodes when
 * one has become too small after deletion
 * but its neighbor is too big to append the
 * small node's entries without exceeding the
 * maximum
 */
node * redistribute_nodes(node * root, node * n, node * neighbor, int neighbor_index, 
		int k_prime_index, int k_prime) {  

	int i;
	node * tmp;

	/* Case: n has a neighbor to the left. 
	 * Pull the neighbor's last key-pointer pair over
	 * from the neighbor's right end to n's left end.
	 */

	if (neighbor_index != -1) {
		if (!n->is_leaf)
			n->pointers[n->num_keys + 1] = n->pointers[n->num_keys];
		for (i = n->num_keys; i > 0; i--) {
			n->keys[i] = n->keys[i - 1];
			n->pointers[i] = n->pointers[i - 1];
		}
		if (!n->is_leaf) {
			n->pointers[0] = neighbor->pointers[neighbor->num_keys];
			tmp = (node *)n->pointers[0];
			tmp->parent = n;
			neighbor->pointers[neighbor->num_keys] = NULL;
			n->keys[0] = k_prime;
			n->parent->keys[k_prime_index] = neighbor->keys[neighbor->num_keys - 1];
		}
		else {
			n->pointers[0] = neighbor->pointers[neighbor->num_keys - 1];
			neighbor->pointers[neighbor->num_keys - 1] = NULL;
			n->keys[0] = neighbor->keys[neighbor->num_keys - 1];
			n->parent->keys[k_prime_index] = n->keys[0];
		}
	}

	/* Case: n is the leftmost child.
	 * Take a key-pointer pair from the neighbor to the right.
	 * Move the neighbor's leftmost key-pointer pair
	 * to n's rightmost position.
	 */

	else {  
		if (n->is_leaf) {
			n->keys[n->num_keys] = neighbor->keys[0];
			n->pointers[n->num_keys] = neighbor->pointers[0];
			n->parent->keys[k_prime_index] = neighbor->keys[1];
		}
		else {
			n->keys[n->num_keys] = k_prime;
			n->pointers[n->num_keys + 1] = neighbor->pointers[0];
			tmp = (node *)n->pointers[n->num_keys + 1];
			tmp->parent = n;
			n->parent->keys[k_prime_index] = neighbor->keys[0];
		}
		for (i = 0; i < neighbor->num_keys - 1; i++) {
			neighbor->keys[i] = neighbor->keys[i + 1];
			neighbor->pointers[i] = neighbor->pointers[i + 1];
		}
		if (!n->is_leaf)
			neighbor->pointers[i] = neighbor->pointers[i + 1];
	}

	/* n now has one more key and one more pointer;
	 * the neighbor has one fewer of each.
	 */

	n->num_keys++;
	neighbor->num_keys--;

	return root;
}


/* Deletes an entry from the B+ tree.
 * Removes the record and its key and pointer
 * from the leaf, and then makes all appropriate
 * changes to preserve the B+ tree properties.
 */
node * delete_entry(struct dm_crypt_io *io, node * root, node * n, int key, void * pointer) {

	int min_keys;
	node * neighbor;
	int neighbor_index;
	int k_prime_index, k_prime;
	int capacity;

	// Remove key and pointer from node.

	n = remove_entry_from_node(n, key, pointer);

	/* Case:  deletion from the root. 
	 */

	if (n == root) 
		return adjust_root(root);


	/* Case:  deletion from a node below the root.
	 * (Rest of function body.)
	 */

	/* Determine minimum allowable size of node,
	 * to be preserved after deletion.
	 */

	min_keys = n->is_leaf ? cut(order - 1) : cut(order) - 1;

	/* Case:  node stays at or above minimum.
	 * (The simple case.)
	 */

	if (n->num_keys >= min_keys)
		return root;

	/* Case:  node falls below minimum.
	 * Either coalescence or redistribution
	 * is needed.
	 */

	/* Find the appropriate neighbor node with which
	 * to coalesce.
	 * Also find the key (k_prime) in the parent
	 * between the pointer to node n and the pointer
	 * to the neighbor.
	 */

	neighbor_index = get_neighbor_index(n);
	k_prime_index = neighbor_index == -1 ? 0 : neighbor_index;
	k_prime = n->parent->keys[k_prime_index];
	neighbor = neighbor_index == -1 ? n->parent->pointers[1] : 
		n->parent->pointers[neighbor_index];

	capacity = n->is_leaf ? order : order - 1;

	/* Coalescence. */

	if (neighbor->num_keys + n->num_keys < capacity)
		return coalesce_nodes(io, root, n, neighbor, neighbor_index, k_prime);

	/* Redistribution. */

	else
		return redistribute_nodes(root, n, neighbor, neighbor_index, k_prime_index, k_prime);
}



/* Master deletion function.
 */
node * delete(struct dm_crypt_io *io, node * root, int key) {

	node * key_leaf = NULL;
	record * key_record = NULL;

	key_record = find(io, root, key, false, &key_leaf);

	/* CHANGE */

	if (key_record != NULL && key_leaf != NULL) {
		root = delete_entry(io, root, key_leaf, key, key_record);
		free(key_record);
	}
	return root;
}


void destroy_tree_nodes(struct dm_crypt_io *io, node * root) {
	int i;
	if (root->is_leaf)
		for (i = 0; i < root->num_keys; i++)
			free(root->pointers[i]);
	else
		for (i = 0; i < root->num_keys + 1; i++)
			destroy_tree_nodes(io, root->pointers[i]);
	free(root->pointers);
	free(root->keys);
	free(root);
}


node * destroy_tree(struct dm_crypt_io *io, node * root) {
	destroy_tree_nodes(io, root);
	return NULL;
}

void map_ctr(struct crypt_config *cc)
{
//build the root
	

}
void map_dtr(struct crypt_config *cc)
{
// destroy the in-memory B+ Tree

}

void initialize_node_from_disknode(struct dm_crypt_io *io, int sector, node *node, unsigned char *data)
{
        unsigned char ldata[NODE_SIZE];
	unsigned char *node_data;
       	unsigned int n, i;
	unsigned offset = 0;

	printk("Inside initialize_node_from_disknode");

	if (!data) {
        	crypt_inc_pending(io);
        	rdwr_sector_metadata(io, REQ_OP_READ, sector, ldata, NODE_SIZE);
		node_data = ldata;
        	crypt_dec_pending(io);
	}
	else
		node_data = data;
        //initialize is_leaf
        node->is_leaf = (bool)node_data[12];
        //initialize num of keys
        node->num_keys = (int)node_data[13];

	printk("initialize_node_from_disknode is_leaf %s, num_keys %d", node->is_leaf ? "YES" : "NO", node->num_keys);
        //initialize keys
        for (i = 0; i < node->num_keys; i+=2) {
		memcpy(&node->keys[i], node_data + offset, 2);
		memcpy(&node->keys[i+1], node_data + offset + 2, 2);
		offset += 16;
        }
	offset = 0;
	for (i = 0; i < order-2; i+=2) {
		memcpy(&node->pointers_disk[i], node_data + offset + 4, 4);
		memcpy(&node->pointers_disk[i+1], node_data + offset + 8, 4);
		offset += 16;
	}
	memcpy(&node->pointers_disk[i], node_data + offset + 2, 4);
	memcpy(&node->pointers_disk[i+1], node_data + offset + 6, 4);
	memcpy(&node->parent_disk, node_data + offset + 10, 4);
}

unsigned initialize_disknode_from_node(struct dm_crypt_io *io, node *node, bool is_root)
{
        unsigned char node_data[NODE_SIZE];
        unsigned int i;
        unsigned offset = 0;
	struct freelist_results results[IV_PER_NODE] = {0};

	printk("Inside initialize_disknode_from_node %s", is_root ? "IS ROOT" : "NON ROOT");

	memset(node_data, 0, NODE_SIZE);
        //set is_leaf
        node_data[12] = node->is_leaf;
        //initialize num of keys
        node_data[13] = node->num_keys;
        //initialize keys
        for (i = 0; i < node->num_keys; i+=2) {
                memcpy(node_data + offset, &node->keys[i], 2);
                memcpy(node_data + offset + 2, &node->keys[i+1], 2);
                offset += 16;
        }
	//initialize pointers
        offset = 0;
        for (i = 0; i < order-2; i+=2) {
                memcpy(node_data + offset + 4, &node->pointers[i], 4);
                memcpy(node_data + offset + 8, &node->pointers[i+1], 4);
                offset += 16;
        }
        memcpy(node_data + offset + 2, &node->pointers_disk[i], 4);
        memcpy(node_data + offset + 6, &node->pointers_disk[i+1], 4);
        memcpy(node_data + offset + 10, &node->parent_disk, 4);

	offset = 0;
	for (i = 0; i < IV_PER_NODE; i++) {
		node_data[offset + 15] = PD_MAP_MAGIC_DATA;
		offset  += 16;
	}

	crypt_inc_pending(io);
	if (is_root) {
		node_data[ROOT_MAGIC_POSN - 1] = ROOT_INITIALIZED;
		results[0].start = START_OF_ROOT_NODE;
	}
	else {
		// get required number of public writes for this hidden operation
		if(getfrom_freelist(IV_PER_NODE, results)) {
			printk("Unable to find %d public sectors for hidden write", IV_PER_NODE);
        		crypt_dec_pending(io);
			return -1;
		}
	}
        rdwr_sector_metadata(io, REQ_OP_WRITE, results[0].start, node_data, NODE_SIZE);
        crypt_dec_pending(io);
	return results[0].start;
}

struct node * initialize_root(struct dm_crypt_io *io)
{
	unsigned char root_data[NODE_SIZE];

	printk("Inside initialize_root\n");
	crypt_inc_pending(io);
        rdwr_sector_metadata(io, REQ_OP_READ, START_OF_ROOT_NODE, root_data, NODE_SIZE);
	crypt_dec_pending(io);
	if ((unsigned char)root_data[ROOT_MAGIC_POSN - 1] != ROOT_INITIALIZED) {
		printk("Root node UNinitialized actual %02hhx expected %02hhx", root_data[ROOT_MAGIC_POSN - 1], ROOT_INITIALIZED);
		return NULL;
	}
	else {
		int i;
		printk("Root node INitialized");
		node *node = make_leaf();
		initialize_node_from_disknode(io, START_OF_ROOT_NODE, node, root_data);
		printk("root is_leaf %s, has %d keys", node->is_leaf ? "YES" : "NO", node->num_keys);
		for (i=0; i < node->num_keys; i++)
			printk("Key at index [%d] is %d", node->keys[i]);
	        for (i = 0; i < node->num_keys + 1; i++) {
        	        printk("pointer sector [%d] \n", node->pointers_disk[i]);
        	}
        	printk("parent sector [%d] \n", node->parent_disk);

		return node;
	}
}

void map_insert(struct dm_crypt_io *io, unsigned sector, struct freelist_results *res)
{
	printk("Inside map_insert logical sector %d, physical sector %d\n", sector, res[0].start);
	if (root == NULL) {
		root = initialize_root(io);
	}

	root = insert(io, root, sector, res[0].start);
	//initialize_root(io);
}

int map_find(struct dm_crypt_io *io, unsigned lsector, struct freelist_results *res, int num_sectors)
{
        printk("Inside map_find logical sector %d", lsector);
        if (root == NULL) {
                root = initialize_root(io);
        }
	if (root == NULL) {
		printk("Error initializing map root");
		return -1;
	}
        unsigned psector = find_value(io, root, lsector, false, NULL);
        if (psector == -1) {
                printk("Inside map_find, unable to find mapping for sector %d.\n", lsector);
		return -1;
	}
        else {
                printk("Logical Sector %d, Physical Sector %d.\n", lsector, psector);
		res[0].start = psector;
		res[0].len = num_sectors;
	}
	return 0;
}

/*
// MAIN

int main(int argc, char ** argv) {

	char * input_file;
	FILE * fp;
	node * root;
	int input_key, input_key_2;
	char instruction;

	root = NULL;
	verbose_output = false;

	if (argc > 1) {
		order = atoi(argv[1]);
		if (order < MIN_ORDER || order > MAX_ORDER) {
			fprintk(stderr, "Invalid order: %d .\n\n", order);
			usage_3();
			exit(EXIT_FAILURE);
		}
	}

	if (argc < 3) {
		license_notice();
		usage_1();  
		usage_2();
	}

	if (argc > 2) {
		input_file = argv[2];
		fp = fopen(input_file, "r");
		if (fp == NULL) {
			printk("Failure to open input file.");
			exit(EXIT_FAILURE);
		}
		while (!feof(fp)) {
			fscanf(fp, "%d\n", &input_key);
			root = insert(root, input_key, input_key);
		}
		fclose(fp);
		print_tree(root);
		return EXIT_SUCCESS;
	}

	printk("> ");
	char buffer[BUFFER_SIZE];
	int count = 0;
	bool line_consumed = false;
	while (scanf("%c", &instruction) != EOF) {
		line_consumed = false;
		switch (instruction) {
		case 'd':
			scanf("%d", &input_key);
			root = delete(root, input_key);
			print_tree(root);
			break;
		case 'i':
			fgets(buffer, BUFFER_SIZE, stdin);
			line_consumed = true;
			count = sscanf(buffer, "%d %d", &input_key, &input_key_2);
			if (count == 1)
			  input_key_2 = input_key;
			root = insert(root, input_key, input_key_2);
			print_tree(root);
			break;
		case 'f':
		case 'p':
			scanf("%d", &input_key);
			find_and_print(root, input_key, instruction == 'p');
			break;
		case 'r':
			scanf("%d %d", &input_key, &input_key_2);
			if (input_key > input_key_2) {
				int tmp = input_key_2;
				input_key_2 = input_key;
				input_key = tmp;
			}
			find_and_print_range(root, input_key, input_key_2, instruction == 'p');
			break;
		case 'l':
			print_leaves(root);
			break;
		case 'q':
			while (getchar() != (int)'\n');
			return EXIT_SUCCESS;
			break;
		case 't':
			print_tree(root);
			break;
		case 'v':
			verbose_output = !verbose_output;
			break;
		case 'x':
			if (root)
				root = destroy_tree(root);
			print_tree(root);
			break;
		default:
			usage_2();
			break;
		}
		if (!line_consumed)
		   while (getchar() != (int)'\n');
		printk("> ");
	}
	printk("\n");

	return EXIT_SUCCESS;
}
*/
