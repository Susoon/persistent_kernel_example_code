#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "memory.cu.h"
#include "util.cu.h"
#include "log.h"
#include "dummy_pkts.h"
#include "router.h"
#include "nids.h"
#include "ipsec.h"

#include <cuda.h>

#define NUM_OF_PERSISTENT_KERNEL 3

__global__ void set_dummy_pkts(struct mempool** mempool, uint32_t num_entries, uint32_t entry_size, uint16_t pkt_size){

	uint32_t mini_mpool_entries = num_entries / DEFAULT_DESC_NUM;
	struct mempool* mini_mempool;
	if(!pkt_size)
		return;
	for(int i = 0; i < DEFAULT_DESC_NUM; i++) {
		mini_mempool = mempool[i];
		for(int j = 0; j < mini_mpool_entries; j++) {
			struct pkt_buf* buf = (struct pkt_buf*) (((uint8_t*)((mini_mempool)->base_addr)) + j * entry_size);
			switch(pkt_size) {
				case 64:
					memcpy((buf->data), pkt_60B, pkt_size);
					buf->paylen = pkt_size;
					break;
				case 128:
					memcpy((buf->data), pkt_124B, pkt_size);
					buf->paylen = pkt_size;
					break;
				case 256:
					memcpy((buf->data), pkt_252B, pkt_size);
					buf->paylen = pkt_size;
					break;
				case 512:
					memcpy((buf->data), pkt_508B, pkt_size);
					buf->paylen = pkt_size;
					break;
				case 1024:
					memcpy((buf->data), pkt_1020B, pkt_size);
					buf->paylen = pkt_size;
					break;
				case 1514:
					memcpy((buf->data), pkt_1510B, pkt_size);
					buf->paylen = pkt_size;
					break;
			}
		}
	}
	START_RED
	printf("[%s] Dummy pkt setting is completed. (%d) Bytes.\n", __FUNCTION__, pkt_size);
	END
}

int main(int argc, char** argv){

	struct mempool** d_mempool = NULL; // For mini-mempool of each GPU thread.
	uint32_t mempool_entries = 512*4; // number of "Pkt buffers".
	uint32_t mempool_entry_size = 2048; // size of a "Pkt buffer".

	init_mempool(&d_mempool, mempool_entries, mempool_entry_size, NUM_OF_PERSISTENT_KERNEL);

    printf("[%s] init mempool Done!\n", __FUNCTION__);

	// After select gpu!
	uint32_t *pkt_cnt = NULL, *pkt_size = NULL;
	// For monitoring
    printf("[%s] cudaMalloc start!\n", __FUNCTION__);
	ASSERTRT(cudaMalloc((void**)&pkt_cnt, sizeof(uint32_t)*2));
	ASSERTRT(cudaMalloc((void**)&pkt_size, sizeof(uint32_t)));
	ASSERTRT(cudaMemset(pkt_cnt, 0, sizeof(uint32_t)*2));
	ASSERTRT(cudaMemset(pkt_size, 0, sizeof(uint32_t)));
    printf("[%s] cudaMalloc Done!\n", __FUNCTION__);

	set_dummy_pkts<<<1, 1>>> (d_mempool, mempool_entries, mempool_entry_size, (uint16_t)(atoi(argv[1])));
	cudaDeviceSynchronize();

	//initialize_router(d_mempool , pkt_cnt);
	initialize_nids(d_mempool, pkt_cnt);
	//initialize_ipsec(d_mempool, pkt_cnt);

#if 0
	monitoring_loop(&pkt_cnt, &pkt_size);
#else
    while(true){
        sleep(1);
    }
#endif

    cudaDeviceSynchronize();

	return 0;
}
