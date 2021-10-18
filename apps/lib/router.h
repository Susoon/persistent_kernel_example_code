#ifndef __ROUTER_H_
#define __ROUTER_H_

#include <stdint.h>
#include <stdio.h>
#include "memory.cu.h"
#include "util.cu.h"
#include "log.h"
#include "pkt_data.h"
#include <stdint.h>
#include <stdio.h>
#include <linux/ip.h> 
#include <linux/if_ether.h>
#include <sys/time.h>  // CKJUNG, 18.08.31 For rusage (Resource Usage)
#include <sys/resource.h>  // CKJUNG, 18.08.31 For rusage (Resource Usage)


//__device__ void d_interface_lookup(uint32_t *IP_lookup, short *d_mtable, short *d_stable);
//__global__ void router(struct pkt_buf *p_buf, short* d_mtable, short* d_stable, int* pkt_cnt);

#define NUM_TURN_router 2

/********************************************************************  
 * Constant definitions (18.08.22)                                               
 ********************************************************************/ 
#define MTABLE_ENTRIES_LENGTH 16777216 // 2^24 entries (18.08.31)

#define OUTPUT_NAME ".out"                                             
#define OK 0                                                           
#define ROUTING_TABLE_NOT_FOUND -3000                                  
#define INPUT_FILE_NOT_FOUND -3001                                     
#define BAD_ROUTING_TABLE -3002                                        
#define REACHED_EOF -3003                                              
#define BAD_INPUT_FILE -3004                                           
#define PARSE_ERROR -3005                                              
#define CANNOT_CREATE_OUTPUT -3006                                     

/*********************************************************************** 
 * Funtions related to initialize NF#1.router                          
 ***********************************************************************/
int initializeIO(char *routingTableName, char *inputFileName);
void freeIO();
void printIOExplanationError(int result);
int readFIBLine(uint32_t *prefix, int *prefixLength, int *outInterface);
int readInputPacketFileLine(uint32_t *IPAddress);
void printOutputLine(uint32_t IPAddress, int outInterface, struct timeval *initialTime, struct timeval *finalTime,
		double *searchingTime, int numberOfHashtables);
void printMemoryTimeUsage();
void printSummary(int processedPackets, double averageTableAccesses, double averagePacketProcessingTime);
void initializeFIB();
void interface_lookup(uint32_t *IP_lookup, short int *ntables,unsigned short *interface);
void compute_routes();

extern "C"
void initialize_router(struct mempool **mempool, uint32_t *pkt_cnt);




#endif /* __ROUTER_H_ */

