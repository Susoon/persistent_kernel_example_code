#ifndef __NIDS_H_
#define __NIDS_H_

#include <linux/if_ether.h>
#include <linux/ip.h>      
#include <linux/udp.h>
#include <queue>
#include <stdint.h>
#include "icmp.cu.h"
#include "memory.cu.h"
#include "util.cu.h"
#include "log.h"
#include "pkt_data.h"

using namespace std;

#define NUM_TURN_nids 2

// CKJUNG, 19.03.22 For NIDS, portGroup
#define LINE_LENGTH 100
#define MAXC 256
#define MAX_PORTS 65536
struct portGroup{                                                        
	// Status info //---------------------                                 
	int dstPortMap[MAX_PORTS]; // Existence of Trie for each port (1 or 0).
	int dstTrieDepth[MAX_PORTS]; // Depth of each Trie if it exists.       

	// Real data //----------------------                                  
	int **dstTrie; // TRIE (2-dimension).                                  
	int **dstFailure; // Failure_state (1-dimension).                      
	int **dstOutput; // Output_state (1-dimension).                        
};

extern "C"
void initialize_nids(struct mempool **mempool, uint32_t *pkt_cnt);

__device__ int lookup2D(int* trie, int col, int row);
__device__ int lookup1D(int* arr, int point); 

#define TOUPPER(x) ((x - 'a') + 'A')

#define NIDS_THPERPKT 3


#endif /* __NIDS_H_ */
