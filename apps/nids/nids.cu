#include "nids.h"

//CKJUNG, 19.03.22 NIDS functions
__device__ int lookup2D(int* trie, int col, int row)
{ 
	if(row == -1)
		row = 0;
	return trie[row*MAXC + col];
} 

__device__ int lookup1D(int* arr, int point) 
{ 
	if(point == -1)
		point = 0; 
	return arr[point];
} 

__global__ void testtt(void) {
	START_YLW
	printf("_______________[%s] HELLO!!!__________________\n", __FUNCTION__);
	END
}

// CKJUNG, 19.01.30 [NF#3:NIDS]------------------------------------- 
__global__ void nids(struct mempool** mempool, uint32_t* pkt_cnt, int** d_dstTrie, int** d_dstFailure, int** d_dstOutput, struct portGroup *d_pg)
{ 
	int i;
	__shared__ unsigned char xlatcase[256];

	int tid = blockDim.x * blockIdx.x + threadIdx.x;
	int pktid = tid / THD_PER_PKT;
	int dataid = tid % THD_PER_PKT;

	struct pkt_buf* buf = NULL;
	__shared__ struct pkt_buf* buf_pool[512];
	struct mempool* mini_mempool = NULL;
	if(pktid < 512)
		mini_mempool = mempool[pktid];

	if(threadIdx.x == 0){
		for(i = 0; i < 256; i++)
			xlatcase[i] = (unsigned char)TOUPPER(i); // Init xlatcase : Convert Lower to Upper
		for(int i = 0; i < 512; i++)
			buf_pool[i] = NULL;
	}

#if 0 

	if(threadIdx.x == NF_T_NUM - 1){
		START_RED
		printf("[%s] threadIdx.x %d is alive!\n", __FUNCTION__, threadIdx.x);
		END
	}
#endif

	
	while(true) { //Persistent Kernel
		__syncthreads();
		if(pktid < 512){
			if(dataid == 0){
				buf_pool[pktid] = pkt_buf_alloc(mini_mempool);
				//buf_pool[pktid] = pkt_buf_extract(mini_mempool, 1);
            }

			__syncthreads();
			buf = buf_pool[pktid];
			if(buf != NULL){
#if 1 
				struct udphdr* udph = (struct udphdr *)(buf->data + sizeof(struct ethhdr) + sizeof(struct iphdr));

				// Extract "portNUM" & "Length of payload"
				int dst_port = NTOHS(udph->dest);
				//int payload_len = (int)NTOHS(udph->len) - sizeof(struct udphdr);
				int payload_len = PKT_DATA_SIZE - 42;
		
				unsigned char* payload = buf->data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + dataid*DATA_PER_THD;

				int y = 0, r, s, cnt = 0;
				r = 0;
				int ret = 0;
				int curPoint = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + dataid*DATA_PER_THD;

				if(d_pg->dstPortMap[dst_port] == NULL){
				}else{
					int *tmp_trie = d_dstTrie[dst_port];
					int *tmp_failure = d_dstFailure[dst_port];
					int *tmp_output = d_dstOutput[dst_port];

					while(y + curPoint < PKT_SIZE){
						if(payload[y]>='a' && payload[y]<='z') // Convert Lower to Upper
							payload[y] = xlatcase[payload[y]];

						// string matching with Trie and Failure link
						while((s = lookup2D(tmp_trie, payload[y], r)) == -1){
							r = lookup1D(tmp_failure, r);
						}
						if(s == 0){
							if(y >= payload_len/THD_PER_PKT)
								break;
						}
						r = s;
						ret = lookup1D(tmp_output, r);
						cnt += ret;
						y++;
					}				
				}
				//memset(payload, 0, 10);
				//memcpy(payload + 2, &dst_port, sizeof(int));
				//memset(payload + 6, 0, 4);

#endif
				__syncthreads();
				if(dataid == 0){
/*
					buf->app_idx = 2;
					buf = NULL;
*/
                    pkt_buf_free(&(buf));
                    atomicAdd(&pkt_cnt[1], 1);
					buf_pool[pktid] = NULL;
				}
			}
		}
	}
}
	// ~CKJUNG, ---------------------------------------------------------- 

extern "C"
void initialize_nids(struct mempool** mempool, uint32_t *pkt_cnt)
{
#if 1
	// CKJUNG, 19.03.22 [NF #3: NIDS] Setting DST TRIEs, Failures, Outputs /////////////////////////
	char buf[30]; 
	char *tok;
	int portNum; 
	int i, j;

	queue<int> q;

	printf("____[Initialize]__NF #3__NIDS__\n");
	// DRAM : TRIEs, Failures, Outputs 
	struct portGroup pg;
	memset(&pg, 0, sizeof(struct portGroup)); 
	pg.dstTrie = (int**)calloc(sizeof(int*),MAX_PORTS); 
	pg.dstFailure = (int**)calloc(sizeof(int*),MAX_PORTS); 
	pg.dstOutput = (int**)calloc(sizeof(int*),MAX_PORTS);

	// GDDR : TRIEs, Failures, Outputs 
	struct portGroup *d_pg;
	ASSERTRT(cudaMalloc((void**)&d_pg, sizeof(struct portGroup))); 
	ASSERTRT(cudaMemset(d_pg, 0, sizeof(struct portGroup)));

	// [TODO] 19.03.22. How to access "Double pointer in struct which is in GPU?"
	int **d_dstTrie; 
	int **d_dstFailure; 
	int **d_dstOutput;
	ASSERTRT(cudaMalloc((void**)&d_dstTrie, sizeof(int*)*MAX_PORTS));
	ASSERTRT(cudaMalloc((void**)&d_dstFailure, sizeof(int*)*MAX_PORTS));
	ASSERTRT(cudaMalloc((void**)&d_dstOutput, sizeof(int*)*MAX_PORTS)); 

	FILE* fp = fopen("./apps/lib/ck_dst_trie.txt","r");

	while((fgets(buf, LINE_LENGTH, fp)) != NULL)
	{ 
		if(!strcmp(buf, " ")||!strcmp(buf, "\n")) 
			continue; 
		// CKJUNG, For port Num
		tok = strtok(buf, " ");
		if(!strcmp(tok, "dst")){ 
			portNum = atoi(strtok(NULL, " ")); 
		}else if(!strcmp(tok, "src")){
			portNum = atoi(strtok(NULL, " ")); 
		}else{ // Gen or After portNum
			int Depth = atoi(buf); 
			if(Depth == 0) // If meaningless then continue,,
				continue;
			// CKJUNG, Initialize Array 
			int arr[Depth][MAXC];
			for(i = 0; i < Depth; i++)
				for(j = 0; j < MAXC; j++) 
					arr[i][j] = -1; 
			// ~CKJUNG

			pg.dstOutput[portNum] = (int*)malloc(sizeof(int)*(Depth+1));
			for(i = 0; i < Depth+1; i++)
				(pg.dstOutput[portNum])[i] = 0;

			// CKJUNG, Fill the Array
			int prev = -1;
			int ptnLen = 0;
			int numPtn = 1;
			for(i = 0; i < Depth; i++)
			{
				int stateNum;
				int row, col;
				fgets(buf, LINE_LENGTH, fp);
				//printf("buf: %s\n", buf); 
				stateNum = atoi(strtok(buf, ":"));
				tok = strtok(NULL, ":");
				row = atoi(strtok(tok, " "));
				if(prev > row){ 
					ptnLen = 1;
					numPtn++;
					pg.dstOutput[portNum][stateNum-1] = 1; // Filling Output vector 1.
				}else if(i == Depth-1){
					ptnLen++;
					pg.dstOutput[portNum][stateNum] = 1; // Filling Output vector 2.
				}else{
					ptnLen++;
				}
				prev = row;
				col = atoi(strtok(NULL, " ")); 
				arr[row][col] = stateNum; 
			} 

			// 1st Row should be filled by "zeroes". 
			// Because they are root nodes
			for(i = 0; i < MAXC; i++)
				if(arr[0][i] == -1)
					arr[0][i] = 0;

			//CKJUNG, [TODO, 19.02.18 16:43] Making failure State

			// Initialize Failure link as -1
			int oo;
			pg.dstFailure[portNum] = (int*)malloc(sizeof(int)*(Depth+1)); 
			for(oo = 0; oo < Depth+1; oo++) 
				(pg.dstFailure[portNum])[oo] = -1; 

			// Initiailize Failure link of root node as 0(root)
			int ch;
			for(ch = 0; ch < MAXC; ch++)
			{ 
				// If root node has some child nodes
				if(arr[0][ch] != 0) 
				{
					(pg.dstFailure[portNum])[arr[0][ch]] = 0;
					q.push(arr[0][ch]);
				}
			} 

			while(q.size())
			{ 
				int state = q.front(); 
				if(state >= Depth)
					break;
				q.pop();
				for(ch = 0; ch < MAXC; ch++)
				{
					if(arr[state][ch] != -1)
					{
						int failure = (pg.dstFailure[portNum])[state];
						while(arr[failure][ch] == -1) 
							failure = (pg.dstFailure[portNum])[failure]; 

						failure = arr[failure][ch]; 
						(pg.dstFailure[portNum])[arr[state][ch]] = failure; 

						(pg.dstOutput[portNum])[arr[state][ch]] += (pg.dstOutput[portNum])[failure]; 
						q.push(arr[state][ch]); 
					} 
				}
			} 

			//[THINK] Every time we malloc here, we get NEW ADDRESS for each TRIE, CKJUNG 
			pg.dstTrie[portNum] = (int*)malloc(sizeof(int)*Depth*MAXC); 
			for(i = 0; i < Depth; i++) 
				for(j = 0; j < MAXC; j++) 
					pg.dstTrie[portNum][i*MAXC+j] = arr[i][j]; 

			//[THINK] We SHOULDN'T FREE "brr" until the end of the program!!, CKJUNG
			pg.dstPortMap[portNum] = 1; // Set portMap 
			pg.dstTrieDepth[portNum] = Depth; 
		} // We've read all
	}

	///////////////////////////// CKJUNG, Copy Tries to GPU /////////////////////////////////////// 
	int *tmp_trie[MAX_PORTS]; 
	int *tmp_failure[MAX_PORTS]; 
	int *tmp_output[MAX_PORTS];
	for(i = 0; i < MAX_PORTS; i++){
		if(pg.dstPortMap[i] == 1){ // If "this port" has a TRIE,
			// CKJUNG, cudaMemcpy "PortMap" & "Depth" for dst
			ASSERTRT(cudaMemcpy(&(d_pg->dstPortMap[i]),&(pg.dstPortMap[i]), sizeof(int), cudaMemcpyHostToDevice)); 
			ASSERTRT(cudaMemcpy(&(d_pg->dstTrieDepth[i]),&(pg.dstTrieDepth[i]), sizeof(int), cudaMemcpyHostToDevice));

			// CKJUNG, cudaMalloc "Trie" & "Failure" & "Output" for GDDR
			ASSERTRT(cudaMalloc((void**)&tmp_trie[i], (pg.dstTrieDepth[i])*MAXC*sizeof(int))); 
			ASSERTRT(cudaMalloc((void**)&tmp_failure[i], (pg.dstTrieDepth[i]+1)*sizeof(int))); 
			ASSERTRT(cudaMalloc((void**)&tmp_output[i], (pg.dstTrieDepth[i]+1)*sizeof(int)));

			// CKJUNG, cudaMemcpy "Trie" & "Failure" & Output" to GDDR 
			ASSERTRT(cudaMemcpy(tmp_trie[i], pg.dstTrie[i], (pg.dstTrieDepth[i])*MAXC*sizeof(int), cudaMemcpyHostToDevice)); 
			ASSERTRT(cudaMemcpy(tmp_failure[i], pg.dstFailure[i], (pg.dstTrieDepth[i]+1)*sizeof(int), cudaMemcpyHostToDevice));
			ASSERTRT(cudaMemcpy(tmp_output[i], pg.dstOutput[i], (pg.dstTrieDepth[i]+1)*sizeof(int), cudaMemcpyHostToDevice));
		}
	}
	ASSERTRT(cudaMemcpy(d_dstTrie, tmp_trie, sizeof(int*)*MAX_PORTS, cudaMemcpyHostToDevice));
	ASSERTRT(cudaMemcpy(d_dstFailure, tmp_failure, sizeof(int*)*MAX_PORTS, cudaMemcpyHostToDevice)); 
	ASSERTRT(cudaMemcpy(d_dstOutput, tmp_output, sizeof(int*)*MAX_PORTS, cudaMemcpyHostToDevice));

	cudaStream_t cuda_stream4;
	ASSERT_CUDA(cudaStreamCreateWithFlags(&cuda_stream4,cudaStreamNonBlocking));

	START_BLU
	printf("[NIDS] # of Thread Blocks : %d, # of Threads : %d\n", NF_TB_NUM, NF_T_NUM);
	END

	nids<<< NF_TB_NUM, NF_T_NUM, 0, cuda_stream4 >>> (mempool, pkt_cnt, d_dstTrie, d_dstFailure, d_dstOutput, d_pg);

	START_GRN
	printf("[Done]____[Initialize]__NF #3__NIDS__\n");
	printf("[NIDS] %s\n", cudaGetErrorName(cudaGetLastError()));
	END
	// ~ CKJUNG /////////////////////////////////////////////////////////////////////////////
#endif
}

