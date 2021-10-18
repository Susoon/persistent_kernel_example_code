#include "memory.cu.h"
#include "util.cu.h" // GPU_PAGE_MASK
#include "log.h" // ASSERTRT
//#include "../test/dummy_pkts.h"
#include <cuda.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>

/*
 * Memory architecture here is little bit tricky..
 * mpool : (GPU view) "mempool structure" reside in GDDR.
 * d_buf_space : (GPU view) "pkt_buffer_array" in GDDR.
 * gddr_dma_addr : (IXGBE driver's view; PHY addr) "pkt_buffer_array" in GDDR. (for desc info updates) 
 */

__global__ void mem_alloc_mempool(struct mempool *mpool, uint8_t* d_buf_space, uint32_t num_entries, uint32_t entry_size, uint32_t index){

    uint32_t mini_mpool_entries = num_entries / DEFAULT_DESC_NUM;
    (mpool)->num_entries = mini_mpool_entries;
    (mpool)->buf_size = entry_size;
    (mpool)->base_addr = d_buf_space + entry_size * mini_mpool_entries * index;
    (mpool)->free_stack_top = mini_mpool_entries;

    for(uint32_t j = 0; j < mini_mpool_entries; j++){
        (mpool)->free_stack[j] = j;
        struct pkt_buf* buf = (struct pkt_buf*) (((uint8_t*) (mpool)->base_addr) + j * entry_size);
        buf->buf_idx = j;
        buf->app_idx = 0; /* Default value, rx_kernel == 0 */
        buf->mempool = (mpool);
        buf->size = entry_size;
        buf->paylen = 0;
    }
}

void init_mempool(struct mempool*** mpool, uint32_t num_entries, uint32_t entry_size, int num){
	uint8_t* d_buf_space = NULL;
	uint32_t d_buf_size = ((num_entries * entry_size) + GPU_PAGE_SIZE - 1) & GPU_PAGE_MASK;

	START_BLU
	printf("[%s] d_buf_size: %d\n", __FUNCTION__, d_buf_size);
	END

	struct mempool* mini_mempool[DEFAULT_DESC_NUM];
	
	size_t mpool_size = (sizeof(struct mempool*) * DEFAULT_DESC_NUM + GPU_PAGE_SIZE - 1) & GPU_PAGE_MASK;
	
	ASSERTRT(cudaMalloc((void**)mpool, mpool_size));

	printf("[%s] mpool: %p\n", __FUNCTION__, *mpool);
	// Allocating "d_buf_space" in GPU.
	ASSERTRT(cudaMalloc((void**)&d_buf_space, d_buf_size));
	ASSERTRT(cudaMemset(d_buf_space, 0, d_buf_size));

	printf("[%s] d_buf_space: %p\n", __FUNCTION__, d_buf_space);

    uint8_t flag = 1;
    ASSERTDRV(cuPointerSetAttribute(&flag, CU_POINTER_ATTRIBUTE_SYNC_MEMOPS, (CUdeviceptr) d_buf_space));

    printf("[%s] mempool cudamalloc Start!\n", __FUNCTION__);
    // Allocate "mini-mempool structures" in GPU.
    for(uint32_t i = 0; i < DEFAULT_DESC_NUM; i++){
        ASSERTRT(cudaMalloc((void**)&mini_mempool[i], sizeof(struct mempool) + (num_entries / DEFAULT_DESC_NUM) * sizeof(uint32_t)));
        mem_alloc_mempool<<< 1, 1 >>> (mini_mempool[i], d_buf_space, num_entries, entry_size, i);
        cudaDeviceSynchronize();
    }
    printf("[%s] mempool cudamalloc Done!\n", __FUNCTION__);

    ASSERTRT(cudaMemcpy(*mpool, mini_mempool, sizeof(struct mempool*) * DEFAULT_DESC_NUM, cudaMemcpyHostToDevice));
    printf("[%s] mempool cudaMemcpy Done!\n", __FUNCTION__);

}

__device__ struct pkt_buf* pkt_buf_extract(struct mempool* mempool, uint16_t app_idx) {
	struct pkt_buf* buf = NULL;
	int last_idx = mempool->num_entries - 1;
	for(int i = last_idx; i >= 0; i--) {
		buf = (struct pkt_buf*) (((uint8_t*) mempool->base_addr) + i * mempool->buf_size);
		//printf("buf_idx: %d, app_idx : %d\n", buf->buf_idx, buf->app_idx);
		if(buf->app_idx == app_idx){
			//buf->app_idx = 0;
			return buf;
		}
	}
	return NULL;
}

__device__ uint32_t pkt_buf_alloc_batch(struct mempool* mempool, struct pkt_buf* bufs[], uint32_t num_bufs){
	if(mempool->free_stack_top < num_bufs) {
#if 0
		printf("tid [%d] free_stack_top: %d, num_bufs: %d\n", threadIdx.x, mempool->free_stack_top, num_bufs);
		struct pkt_buf* tmp_buf;
		for(int i = 0; i < 4; i++){
			tmp_buf = (struct pkt_buf*) (((uint8_t*) mempool->base_addr) + i * mempool->buf_size);
			printf("tid [%d] buf_idx: %d, app_idx: %d\n", threadIdx.x, tmp_buf->buf_idx, tmp_buf->app_idx);
		}
#endif
		//printf("tid [%d]: memory pool %p only has %d free bufs, requested %d bufs.\n", threadIdx.x, mempool, mempool->free_stack_top, num_bufs);
		num_bufs = mempool->free_stack_top;
	}
	for(uint32_t i = 0; i < num_bufs; i++) {
		atomicAdd(&(mempool->free_stack_top), -1);
		uint32_t entry_id = mempool->free_stack[mempool->free_stack_top];
		//uint32_t entry_id = mempool->free_stack[--mempool->free_stack_top];
		//if(entry_id >= 4)
		//	printf("[%s] entry_id: %d\n", __FUNCTION__, entry_id);
		//uint32_t entry_id = mempool->free_stack[mempool->free_stack_top--];
		bufs[i] = (struct pkt_buf*) (((uint8_t*) mempool->base_addr) + entry_id * mempool->buf_size);
	}
	return num_bufs;
}

__device__ struct pkt_buf* pkt_buf_alloc(struct mempool* mempool) {
	struct pkt_buf* buf = NULL;
	pkt_buf_alloc_batch(mempool, &buf, 1);
	return buf;
}

__device__ void pkt_buf_free(struct pkt_buf** buf) {
	struct mempool* mempool = (*buf)->mempool;
	mempool->free_stack[mempool->free_stack_top] = (*buf)->buf_idx;
	atomicAdd(&(mempool->free_stack_top), 1);
	//mempool->free_stack[mempool->free_stack_top++] = (*buf)->buf_idx;
	//if(mempool->free_stack_top > 4)
	//	printf("[%s] entry_id: %d\n", __FUNCTION__, mempool->free_stack_top);
	(*buf) = NULL;
}

__device__ void pkt_buf_free_fake(struct pkt_buf** buf) {
	(*buf)->data[0] = 0; 
	(*buf)->data[1] = 27;
	(*buf)->app_idx = 0; /* return to base */
	//printf("[%s] pkt_buf(%d) is freed!\n", __FUNCTION__, buf->buf_idx);
	struct mempool* mempool = (*buf)->mempool;
	mempool->free_stack[mempool->free_stack_top++] = (*buf)->buf_idx;
	//if((*buf)->buf_idx > 3) 
	//	printf("__________________________________buf_idx: %d\n", (*buf)->buf_idx);
	(*buf) = NULL;
}



__device__ void print_hello(int tid) {
	printf("Hello world! tid: %d\n", tid);
}


