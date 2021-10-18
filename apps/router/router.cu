#include "router.h"
 
/*********************************************************************** 
 * Static variables for the input/output files                           
 ***********************************************************************/
static FILE *routingTable;                                               
static FILE *inputFile;                                                  
static FILE *outputFile;                                                 


/*********************************************************************** 
 * Variables related to intializing functions below                           
 ***********************************************************************/
int ec;   // In this variable we save the error codes that produces some methods in "io.c"         
/** VARIABLES RELATED with the tables **/                                                                  
short *mtable;    // Main Table                                                                            
short *stable;    // Second Table                                                                          
unsigned short extended_IPs;  // Number of networks using the extended table.                              
/** VARIABLES RELATED WITH THE TABLES INIZIALIZATION **/                                                   
long ip_index;                                                                                             
uint32_t *IP_addr; 
int *aux_prefixLength;                                                                                     
int *aux_outInterface;                                                                                     
/*** VARIABLES RELACIONADAS CON LOOKUP */                                                                  
//struct timeval start, end;                                                                                 
/*** VARIABLES RELATED WITH THE PERFORMANCE INFORMATION*/                                                  
int *processedPackets;                                                                                     
double *totalTableAccesses;                                                                                
double *totalPacketProcessingTime;                                                                         
/*** VARIABLES RELATED WITH GPU NF*/                                                  
short *d_mtable;
short *d_stable;


/*********************************************************************** 
 * ip_v4 lookup function for GPU (18.08.31)
 ***********************************************************************/
__device__ void d_interface_lookup(uint32_t *IP_lookup, short *d_mtable, short *d_stable)
{
	unsigned short interface;

	interface = d_mtable[*IP_lookup>>8];

	if(interface>>16 != 0)
	{
		interface = d_stable[(interface & 0x7FFF)*256 + (*IP_lookup & 0x000000FF)];
	}
	//printf("[CKJUNG]__interface: %d\n", interface);
}

/*********************************************************************** 
 * GPU_NF#1: Router (18.09.17)
 ***********************************************************************/
__global__ void router(struct mempool** mempool, short* d_mtable, short* d_stable, uint32_t* pkt_cnt)
{

	struct mempool* mini_mempool = mempool[threadIdx.x];
	struct pkt_buf* buf = NULL;

	unsigned char* batch_data;

	while(true) { //Persistent Kernel, trick for memory synch, access, blahblah?
#if 1 
		////////////////////////////////// NF's code Here ///////////////////////////////////
		buf = pkt_buf_alloc(mini_mempool);
		//buf = pkt_buf_extract(mini_mempool, 1);

		if(buf != NULL){
			//printf("[Router] tid: %d\n", threadIdx.x);
#if 1
			batch_data = buf->data;
			struct iphdr* iph = (struct iphdr*)(batch_data + sizeof(struct ethhdr));
			uint16_t* _daddr = (uint16_t*)&(iph->daddr);
			uint32_t daddr = 0;

			memcpy(&daddr, _daddr, 4);

			//int ip_len = NTOHS(iph->tot_len);

			//printf("[Router] pkt_size: %d\n", ip_len + 18);

			d_interface_lookup(&daddr, d_mtable, d_stable);
#endif

			atomicAdd(&pkt_cnt[1], 1);
			//buf->app_idx = 2;
			//buf = NULL;
            pkt_buf_free(&(buf));
		}
		////////////////////////////////// NF's code Here ///////////////////////////////////
#endif
	}
	if(threadIdx.x == 0)
		printf("End of gpu_router!\n");
}


/********************************************************************
 * Initalize file descriptors
 *
 * routingTableName contains FIB info (argv[1] of main function)
 * inputFileName contains IP addresses (argv[2] of main function)
 *
 ***********************************************************************/
int initializeIO(char *routingTableName, char *inputFileName){

	char outputFileName[100];

	routingTable = fopen(routingTableName, "r");
	printf("%s\n", routingTableName);
	if (routingTable == NULL) return ROUTING_TABLE_NOT_FOUND;

	inputFile = fopen(inputFileName, "r");
	if (inputFile == NULL) {
		fclose(routingTable);
		return INPUT_FILE_NOT_FOUND;
	}

	sprintf(outputFileName, "%s%s", inputFileName, OUTPUT_NAME);
	outputFile = fopen(outputFileName, "w");
	if (outputFile == NULL) {
		fclose(routingTable);
		fclose(inputFile);
		return CANNOT_CREATE_OUTPUT;
	}

	return OK;
}


/***********************************************************************
 * Close the input/output files
 ***********************************************************************/
void freeIO() {
	fclose(inputFile);
	fclose(outputFile);
	fclose(routingTable);
}


/***********************************************************************
 * Write explanation for error identifier (verbose mode)
 ***********************************************************************/
void printIOExplanationError(int result){
	switch(result) {
		case ROUTING_TABLE_NOT_FOUND:
			printf("Routing table not found\n");
			exit(0);

		case INPUT_FILE_NOT_FOUND:
			printf("Input file not found\n");
			exit(0);

		case BAD_ROUTING_TABLE:
			printf("Bad routing table structure\n");
			exit(0);
		case BAD_INPUT_FILE:
			printf("Bad input file structure\n");
			exit(0);
		case PARSE_ERROR:
			printf("Parse error\n");
			exit(0);
		case CANNOT_CREATE_OUTPUT:
			printf("Cannot create output file\n");
			exit(0);
		case REACHED_EOF:
			printf("Reached End Of File\n");
			exit(0);
		default:
			printf("Unknown error\n");
			exit(0);
	}
	exit(0);
}


/***********************************************************************
 * Read one entry in the FIB
 *
 * It should be noted that prefix, prefixLength and outInterface are
 * pointers since they are used as output parameters
 *
 ***********************************************************************/
int readFIBLine(uint32_t *prefix, int *prefixLength, int *outInterface){
	int n[4], result;
	result = fscanf(routingTable, "%i.%i.%i.%i/%i\t%i\n", &n[0], &n[1], &n[2], &n[3], prefixLength, outInterface);

	// CKJUNG, 18.08.21
	//  printf("\nn0: %d, n1: %d, n2: %d, n3: %d\n", n[0], n[1], n[2], n[3]);
	// ~ CKJUNG

	if (result == EOF) return REACHED_EOF;
	else if (result != 6) return BAD_ROUTING_TABLE;
	else{
		//remember that pentium architecture is little endian
		*prefix = (n[0]<<24) + (n[1]<<16) + (n[2]<<8) + n[3];
		//*prefix = n[0]*pow(2,24) + n[1]*pow(2,16) + n[2]*pow(2,8) + n[3];

		// CKJUNG, 18.08.21
		//printf("prefix : %d\n", *prefix);
		// ~ CKJUNG
		return OK;
	}
}


/***********************************************************************
 * Read one entry in the input packet file
 *
 * Again, it should be noted that IPAddress is a pointer since it is used
 * as output parameter
 *
 ***********************************************************************/
int readInputPacketFileLine(uint32_t *IPAddress){
	int n[4], result;

	result = fscanf(inputFile, "%i.%i.%i.%i\n", &n[0], &n[1], &n[2], &n[3]);
	if (result == EOF) return REACHED_EOF;
	else if (result != 4) return BAD_INPUT_FILE;
	else{
		//remember that pentium architecture is little endian
		*IPAddress = (n[0]<<24) + (n[1]<<16) + (n[2]<<8) + n[3];
		//*IPAddress = n[0]*pow(2,24) + n[1]*pow(2,16) + n[2]*pow(2,8) + n[3];
		return OK;
	}
}


/***********************************************************************
 * Print a line to the output file
 *
 * gettimeofday(&initialTime, NULL) must be called right before the lookup function
 *
 * gettimeofday(&finalTime, NULL) must be called right after the lookup function
 *
 * The lookup function must return (either as output parameter or as return value)
 * the number of hash tables that have been accessed for every IP address
 *
 ***********************************************************************/
void printOutputLine(uint32_t IPAddress, int outInterface, struct timeval *initialTime, struct timeval *finalTime,
		double *searchingTime, int numberOfHashtables) {
	unsigned long sec, usec;
	usec = finalTime->tv_usec - initialTime->tv_usec;
	if (usec > finalTime->tv_usec) initialTime->tv_sec += 1;
	sec = finalTime->tv_sec - initialTime->tv_sec;

	*searchingTime = 1000000*sec + usec;

	//remember that output interface equals 0 means no matching
	//remember that if no matching but default route is specified in the FIB, the default output interface
	//must be stored to avoid dropping the packet (i.e., MISS)
	if (!outInterface){
		fprintf(outputFile,"%i.%i.%i.%i;%s;%i;%.0lf\n",IPAddress >> 24, (IPAddress >> 16) & 0x000000ff, (IPAddress >> 8) & 0x000000ff, IPAddress & 0x000000ff , "MISS",numberOfHashtables, *searchingTime);
	}
	else{
		fprintf(outputFile,"%i.%i.%i.%i;%i;%i;%.0lf\n",IPAddress >> 24, (IPAddress >> 16) & 0x000000ff, (IPAddress >> 8) & 0x000000ff, IPAddress & 0x000000ff , outInterface,numberOfHashtables, *searchingTime);
	}
}


/***********************************************************************
 * Print memory and CPU time   
 *
 * For more info: man getrusage
 *
 ***********************************************************************/   
void printMemoryTimeUsage(){   

	float user_time, system_time;  
	long int memory;   
	struct rusage usage;

	if (getrusage (RUSAGE_SELF, &usage)){  
		printf("Resource measurement failed.\n"); 
	}   
	else{
		user_time = (float)usage.ru_utime.tv_sec+(float)usage.ru_utime.tv_usec/1000000;   
		system_time  = (float)usage.ru_stime.tv_sec+(float)usage.ru_stime.tv_usec/1000000;
		memory = usage.ru_maxrss;  

		fprintf(outputFile, "Memory (Kbytes) = %ld\n", memory ); 
		fprintf(outputFile, "CPU Time (secs)= %.6f\n\n", user_time+system_time);
	}   
}

/***********************************************************************
 * Print execution summary to the output file
 *
 * It should be noted that:
 *
 *averageTableAccesses = totalTableAccesses/processedPackets
 *
 *averagePacketProcessingTime = totalPacketProcessingTime/processedPackets
 *
 ***********************************************************************/
void printSummary(int processedPackets, double averageTableAccesses, double averagePacketProcessingTime){
	fprintf(outputFile, "\nPackets processed= %i\n", processedPackets);
	fprintf(outputFile, "Average table accesses= %.2lf\n", averageTableAccesses);
	fprintf(outputFile,"Average packet processing time (usecs)= %.2lf\n", averagePacketProcessingTime);
	printMemoryTimeUsage();
}

void initializeFIB()
{
	IP_addr = (uint32_t*)calloc(1,sizeof(int));
	aux_prefixLength = (int*)calloc(1,sizeof(int));
	aux_outInterface = (int*)calloc(1,sizeof(int));
	//Now we have the prefix, the ip and the interface
	ec = readFIBLine(IP_addr, aux_prefixLength, aux_outInterface);
	while(ec == 0){  //WHILE NOT EOF OR ANOTHER TYPE OF ERROR
		long int number_of_hosts = 0; // We calculate the number of hosts affected by the mask
		// 2 24 - PREFIJO 
		if(*aux_prefixLength <= 24){
			number_of_hosts = pow(2,24 - *aux_prefixLength);
			for(ip_index = 0; ip_index < number_of_hosts; ip_index++)
			{
				mtable[(*IP_addr>>8) + ip_index] = *aux_outInterface;
			}
		}
		else{
			number_of_hosts = pow(2,32 - *aux_prefixLength);
			if(mtable[*IP_addr>>8]>>15 == 0)  
			{ 
				// 1. REALLOC MEMORY, we reserve 256 more chunks for the new interfaces
				stable = (short*)realloc(stable, 256*(extended_IPs + 1)*2);
				// 2. COPY FROM MTABLE TO STABLE
				// recorremos todo el rango de IP's del ultimo byte de la IP, copiando lo anterior 
				for(ip_index = 0; ip_index <= 255; ip_index++)
				{
					stable[extended_IPs*256 + ip_index] = mtable[*IP_addr>>8];
				}
				// 3. UPDATE MTABLE VALUE WITH THE INDEX OF STABLE
				// We write the "index" to the address in the stable and the bit 1 in the 16th position (0b1000000000000000)
				mtable[*IP_addr>>8] = extended_IPs | 0x8000;
				// 4. POPULATE THE STABLE CHUNK WITH THE SPECIFIED NEW ADDRESS
				for(ip_index = (*IP_addr & 0xFF); ip_index < number_of_hosts + (*IP_addr & 0xFF); ip_index++)
				{
					stable[extended_IPs*256 + ip_index] = *aux_outInterface;
				}
				extended_IPs++;
			}
			else{  // If it already exists a chunk for this Ip range inside stable
				for(ip_index = (*IP_addr & 0xFF); ip_index < number_of_hosts + (*IP_addr & 0xFF); ip_index++)
				{
					stable[(mtable[*IP_addr>>8] & 0x7FFF)*256 + ip_index] = *aux_outInterface;
				}
			}
		}
		//Now we get another IP, interface and interface
		ec = readFIBLine(IP_addr,aux_prefixLength,aux_outInterface);
	}
	free(IP_addr);
	free(aux_prefixLength);
	free(aux_outInterface);
}


/**
 * [Look for an IP address inside the main table and secundary table stored in RAM]
 * Input:
 *IP_lookup
 * Output.
 *interface
 *ntables
 */
void interface_lookup(uint32_t *IP_lookup, short int *ntables,unsigned short *interface)
{
	*interface = mtable[*IP_lookup>>8];
	if(*interface>>15 == 0)
	{
		*ntables = 1;
		return;
	}
	else
	{
		*ntables = 2;
		*interface = stable[(*interface & 0x7FFF)*256 + (*IP_lookup & 0x000000FF)];
		// 0x7fff = 0b0111111111111111 to adquire just the address to the 2nd table
		return;
	}
	return;
}


/**
 * [Perform routing process, going through the file and looking for the best Interface for each IP]
 *
 * Output:
 *processedPackets
 *totalTableAccesses
 *totalPacketProcessingTime
 */
void compute_routes()
{
	uint32_t *IP_lookup = (uint32_t*)calloc(1,sizeof(uint32_t));
	unsigned short *interface = (unsigned short*)calloc(1,sizeof(unsigned short));
	double *searching_time = (double*)calloc(1,sizeof(double));
	short int *number_of_tables = (short int*)calloc(1,sizeof(short int));
	ec = readInputPacketFileLine(IP_lookup);
	while(ec == 0)
	{
		//gettimeofday(&start, NULL);
		interface_lookup(IP_lookup,number_of_tables, interface);
		//gettimeofday(&end, NULL);
		//printOutputLine(*IP_lookup, *interface, &start, &end,searching_time, *number_of_tables);
		*processedPackets = *processedPackets + 1;
		*totalTableAccesses  = *totalTableAccesses + *number_of_tables;
		*totalPacketProcessingTime  = *totalPacketProcessingTime + *searching_time;
		ec = readInputPacketFileLine(IP_lookup);
	}
	free(IP_lookup);
	free(interface);
	free(searching_time);
	free(number_of_tables);
}

extern "C"
void initialize_router(struct mempool** mempool, uint32_t* pkt_cnt)
{
	// CKJUNG, 18.08.22 [NF #1:IP lookup] Setting RIB /////////////////////////////////////////////////////
	//short *d_mtable;
	//short *d_stable;
	printf("____[Initialize]__NF #1__Router__\n");
	ASSERTRT(cudaMalloc((void**)&d_mtable, MTABLE_ENTRIES_LENGTH*sizeof(short)));
	ASSERT_CUDA(cudaMemset(d_mtable, 0, MTABLE_ENTRIES_LENGTH*sizeof(short)));


	mtable = (short*)calloc(MTABLE_ENTRIES_LENGTH, sizeof(short));
	processedPackets = (int*)calloc(1, sizeof(int));
	totalTableAccesses = (double*)calloc(1, sizeof(double));
	totalPacketProcessingTime = (double*)calloc(1, sizeof(double));
	ec = 0;
	extended_IPs = 0;

	ec = initializeIO((char*)"./apps/lib/ck_table", (char*)"./apps/lib/p2"); // Initialize Input
	if(ec != 0){
		printf("\nERROR: \n\t");
		printIOExplanationError(ec);
		//return -1;
	}
	initializeFIB();
	// CKJUNG, size of stable is fixed after initializeFIB
	ASSERTRT(cudaMalloc((void**)&d_stable, 256*(extended_IPs + 1)*2));
	ASSERT_CUDA(cudaMemset(d_stable, 0, 256*(extended_IPs + 1)*2));
	printf("[CKJUNG] initializeFIB() done.\n");
#if 1
	// CKJUNG, copy Routing table from DRAM --> GDDR, Here!
	cudaError_t mtable_err = cudaMemcpy(d_mtable, mtable, MTABLE_ENTRIES_LENGTH*sizeof(short), cudaMemcpyHostToDevice);
	cudaError_t stable_err = cudaMemcpy(d_stable, stable, 256*(extended_IPs + 1)*2, cudaMemcpyHostToDevice);
	if(mtable_err != cudaSuccess || stable_err != cudaSuccess)
	{
		printf("[Error] cudaMemcpy for \"mtable\" or \"stable\" has failed.\n");
	}else{
		START_GRN
			printf("[Router] Routing table (m-table & s-table) is ready.\n");
		END
	}
#endif
			compute_routes();
			printf("[CKJUNG] compute_routes() done. please check \"[InputFileName].out\"\n");
	//		printSummary(*processedPackets, (*totalTableAccesses / *processedPackets), (*totalPacketProcessingTime / *processedPackets));
	freeIO();/* Freeing Resources */
	free(mtable);
	free(stable);
	free(processedPackets);
	free(totalTableAccesses);
	free(totalPacketProcessingTime);


	cudaStream_t cuda_stream2;
	ASSERT_CUDA(cudaStreamCreateWithFlags(&cuda_stream2,cudaStreamNonBlocking));

	printf("NF#1: Router\n");
	router<<< 1, 512, 0, cuda_stream2 >>> (mempool, d_mtable, d_stable, pkt_cnt);

	START_GRN
	printf("[Done]____[Initialize]__NF #1__Router__\n");
	END
//	cudaDeviceSynchronize();
	//return 0;
}


void finalize_router(void)
{
	ASSERT_CUDA(cudaFree(d_mtable));
	ASSERT_CUDA(cudaFree(d_stable));
}
