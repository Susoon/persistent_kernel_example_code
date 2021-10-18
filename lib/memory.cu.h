#ifndef MEMORY_CU_H
#define MEMORY_CU_H

#include <stdint.h>
#include "util.cu.h"

#define DEFAULT_DESC_NUM 512
#define HEADROOM_SIZE 128
#define IPSEC 0 

struct pkt_buf { 
	struct mempool* mempool;
	uint32_t buf_idx;
	uint32_t size; // entry_size
	uint32_t app_idx;
	uint32_t paylen;
	//----------------------- 32 Bytes
	uint8_t pad[96];
	uint8_t headroom[HEADROOM_SIZE];
	uint8_t data[];
	//uint8_t data[] __attribute__((aligned(64)));
};

struct mempool { // Size 24 Bytes (8, 4, 4, 4, 4)
	uint8_t* base_addr; // (GPU virtual addr) mempool area.
	uint32_t buf_size; // entry_size
	uint32_t num_entries; 
	uint32_t free_stack_top;
	uint32_t free_stack[];
};

__device__ uint32_t pkt_buf_alloc_batch(struct mempool* mempool, struct pkt_buf* bufs[], uint32_t num_bufs);
__device__ struct pkt_buf* pkt_buf_alloc(struct mempool* mempool);
__device__ struct pkt_buf* pkt_buf_extract(struct mempool* mempool, uint16_t app_idx);
__device__ void pkt_buf_free(struct pkt_buf** buf);
__device__ void pkt_buf_free_fake(struct pkt_buf** buf);

void init_mempool(struct mempool*** mpool, uint32_t num_entries, uint32_t entry_size, int num);

#endif /* MEMORY_CU_H */
