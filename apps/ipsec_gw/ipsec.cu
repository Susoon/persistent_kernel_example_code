#include "ipsec.h"
#include <stdlib.h>
#include <time.h>

#define SHA 1
#define AES_ASSIGN 1
#define BODY 1

#define EIHDR_SIZE (sizeof(struct ethhdr) + sizeof(struct iphdr))

__device__ void sha1_kernel_global(unsigned char *data, sha1_gpu_context *ctx, uint32_t *extended, int len)
{
#if 1
	/* Initialization vector for SHA-1 */
	ctx->state[0] = 0x67452301; 
	ctx->state[1] = 0xEFCDAB89; 
	ctx->state[2] = 0x98BADCFE; 
	ctx->state[3] = 0x10325476; 
	ctx->state[4] = 0xC3D2E1F0; 

#endif

	uint32_t temp, t;

	/*
	 * Extend 32 block byte block into 80 byte block.
	 */

//sh_kim 20.03.11 : when data length is 20byte, we need padding
	if(len == 20)
	{
		memset(data + len - 1, 0, 44);
	}
	GET_UINT32_BE( extended[0], data,  0 );
	GET_UINT32_BE( extended[1], data,  4 );
	GET_UINT32_BE( extended[2], data,  8 );
	GET_UINT32_BE( extended[3], data, 12 );
	GET_UINT32_BE( extended[4], data, 16 );
	GET_UINT32_BE( extended[5], data, 20 );
	GET_UINT32_BE( extended[6], data, 24 );
	GET_UINT32_BE( extended[7], data, 28 );
	GET_UINT32_BE( extended[8], data, 32 );
	GET_UINT32_BE( extended[9], data, 36 );
	GET_UINT32_BE( extended[10], data, 40 );
	GET_UINT32_BE( extended[11], data, 44 );
	GET_UINT32_BE( extended[12], data, 48 );
	GET_UINT32_BE( extended[13], data, 52 );
	GET_UINT32_BE( extended[14], data, 56 );
	GET_UINT32_BE( extended[15], data, 60 );

	// Same as "blk(i)" macro in openssl source.
	for (t = 16; t < 80; t++) {
		temp = extended[t - 3] ^ extended[t - 8] ^ extended[t - 14] ^ extended[t - 16];
		extended[t] = S(temp,1);
	}

	sha1_gpu_process(ctx, extended);
}

// CKJUNG, 18.10.26 [NF#2:IPSec]-------------------------------------
__global__ void ipsec(struct mempool** mempool, uint32_t* pkt_cnt, unsigned char* d_nounce, unsigned int* d_key, unsigned char* d_sbox, unsigned char* d_GF2, unsigned int* seq)
{
	// 1 ThreadBlock ver.
	// <<< 1, 512 >>> threads. 
	//	1 threads for 1 pkt. (60B pkt)
	// 512 / 1 = 512, 1TB has 512 threads each and manages 512 pkts.

	unsigned char IV[16] = {0};

	sha1_gpu_context octx;
	sha1_gpu_context ictx;
	uint32_t extended[80];
	int ctr = 0;

	int tid = blockDim.x * blockIdx.x + threadIdx.x;
	int pktid = tid / THD_PER_PKT;
	int dataid = tid % THD_PER_PKT;

	unsigned int sha_count = 0;

	struct mempool* mini_mempool = NULL;
	if(pktid < 512)
		mini_mempool = mempool[pktid];

	struct pkt_buf* buf = NULL;
	__shared__ struct pkt_buf* buf_pool[512];

	// 1 ThreadBlock ver.
	// IV : 512 * 16 =  8,192
	// aes_tmp : 512 * (64 - 16) = 24,576
	// octx : 20 * 512 = 10,240
	// pkt_len : 4 * 128 = 512
	//-------------------------- Total __shared__ mem Usage : 43,012 + 512

	if(tid == 0){
		for(int i = 0; i < 512; i++)
			buf_pool[i] = NULL;
	}

#if 0
	if(threadIdx.x == TOTAL_T_NUM - 1){
		START_RED
		printf("[%s] threadIdx.x %d is alive!\n", __FUNCTION__, threadIdx.x);
		END
	}
#endif
	__syncthreads();
	while(true){ // Persistent Kernel (for every threads)
		__syncthreads();
		if(pktid < 512){
			__syncthreads();
			if(dataid == 0){
				buf_pool[pktid] = pkt_buf_alloc(mini_mempool);
				//buf_pool[pktid] = pkt_buf_extract(mini_mempool, 1);
            }

			__syncthreads();
			buf = buf_pool[pktid];
			__syncthreads();
			if(buf != NULL){
#if BODY
				__syncthreads();
				sha_count = PKT_DATA_SIZE / 64 + ((PKT_DATA_SIZE % 64) != 0);
				__syncthreads();
				if(dataid == 0){

					buf->data[PKT_DATA_SIZE] = 0; // padlen
					buf->data[PKT_DATA_SIZE + 1] = IPPROTO_IPIP; // next-hdr (Meaning "IP within IP)

					/* For Reference...
					   IPPROTO_IP = 0
					   IPPROTO_ICMP = 1
					   IPPROTO_IPIP = 4
					   IPPROTO_TCP = 6
					   IPPROTO_UDP = 17
					   IPPROTO_ESP = 50
					 */

					ctr++; // same "ctr" value for grouped 3-threads. (counter) AES-CTR Mode
					IV[15] = ctr & 0xFF;
					IV[14] = (ctr >> 8) & 0xFF; // CKJUNG, 1 Byte = 8bits means, Octal notation
					IV[13] = (ctr >> 16) & 0xFF;
					IV[12] = (ctr >> 24) & 0xFF;

					for(int i = 0; i < 12; i++)
						IV[i] = 0;

					// Copy our state into private memory
					unsigned char temp, temp2;
					unsigned char overflow = 0;
					char tmp[16];
					for(int i = 15; i != -1; i--) {
						temp = d_nounce[i];
						temp2 = IV[i];
						IV[i] += temp + overflow;
						overflow = ((int)temp2 + (int)temp + (int)overflow > 255);
					}

					AddRoundKey(IV, &d_key[0]);

					for(int i = 1; i < 10; i++)
					{
						SubBytes(IV, d_sbox);
						ShiftRows(IV);
						MixColumns(IV, d_GF2, tmp);
						AddRoundKey(IV, &d_key[4 * i]);
					}

					SubBytes(IV, d_sbox);
					ShiftRows(IV);
					AddRoundKey(IV, &d_key[4 * 10]);

					////////////////// Locating AES Encrypted parts into a pkt  ///////////////////////////////

					unsigned char temphdr[34] = { 0 };
					//printf("[tid : %d] data : %ld\n", threadIdx.x, (uint64_t)(buf->data));
					memcpy(temphdr, buf->data, EIHDR_SIZE); 
					memcpy(buf->data - sizeof(struct iphdr) - 8, temphdr, EIHDR_SIZE); 
				}

				__syncthreads();
				for(int i = 0; i < DATA_PER_THD; i++){
					buf->data[sizeof(struct ethhdr) + dataid*DATA_PER_THD + i] ^= IV[i & 15];
				}

				__syncthreads();
				if(dataid == 0){
					//////////// Proto_type = ESP set! ///////////
					buf->data[6] = IPPROTO_ESP; // IPPROTO_ESP = 50
					//buf->data[sizeof(struct ethhdr) + 9 - sizeof(struct iphdr) - 8] = IPPROTO_ESP; // IPPROTO_ESP = 50
					struct esphdr* esph;

					esph = (struct esphdr *)((uint32_t *)&(buf->data[6]));

					// SPI (Security Parameter Index)
					uint32_t spi = 1085899777;
					HTONS32(spi);

					////////// Set ESP header SPI value ///////////////////
					memcpy(&esph->spi, &spi, 4);
					atomicAdd(seq, 1);

					//////////// Set ESP header SEQ value //////////
					memcpy(&esph->seq, seq, 4);

#if	SHA
					// CKJUNG, HMAC-SHA1 From here! /////////////////////////////
					// RFC 2104, H(K XOR opad, H(K XOR ipad, text))
					/**** Inner Digest ****/
					// H(K XOR ipad, text) : 64 Bytes

					int e_index = 0;

					while(e_index < sha_count){
						sha1_kernel_global(&buf->data[6 + e_index*64], &ictx, extended, 64);
						e_index++;
					}
					/**** Outer Digest ****/
					// H(K XOR opad, H(K XOR ipad, text)) : 20 Bytes

					sha1_kernel_global(&(ictx.c_state[0]), &octx, extended, 20);
					memcpy(&buf->data[PKT_DATA_SIZE + 2], &(octx.c_state[0]), 20);
#endif
#endif

/*
					buf->app_idx = 2;
					buf->paylen += 50;
					buf = NULL;
*/
                    atomicAdd(&pkt_cnt[1], 1);
                    pkt_buf_free(&(buf));
					buf_pool[pktid] = NULL;
				}
			}
		}
	}
}

__device__ void AddRoundKey(unsigned char *state, unsigned *w)
{
	int i;                                                              
	for(i = 0; i < BLOCK_SIZE; i++) { // column
		state[i * 4 + 0] = state[i * 4 + 0] ^ ((w[i] >> (8 * 3)) & 0xFF);
		state[i * 4 + 1] = state[i * 4 + 1] ^ ((w[i] >> (8 * 2)) & 0xFF);
		state[i * 4 + 2] = state[i * 4 + 2] ^ ((w[i] >> (8 * 1)) & 0xFF);
		state[i * 4 + 3] = state[i * 4 + 3] ^ ((w[i] >> (8 * 0)) & 0xFF);
	}                                                                   
}

__device__ void SubBytes(unsigned char *state, unsigned char* sbox) //state = 16 chars
{ 
	int i;
	for(i = 0; i < 4 * BLOCK_SIZE; i++) {
		state[i] = sbox[state[i]];
	}
} 

__device__ void ShiftRows(unsigned char *state)
{ 
	// NOTE: For whatever reason the standard uses column-major ordering ?
	// 0 1 2 3 --> 0 1 2 3  | 0  4  8  12 --> 0   4  8 12
	// 0 1 2 3 --> 1 2 3 0  | 1  5  9  13 --> 5   9 13  1
	// 0 1 2 3 --> 2 3 0 1  | 2  6  10 14 --> 10 14  2  6
	// 0 1 2 3 --> 3 0 1 2  | 3  7  11 15 --> 15  3  7 11
	unsigned char temp = state[1];

	state[1] = state[5];
	state[5] = state[9];
	state[9] = state[13];
	state[13] = temp;

	temp = state[2];
	state[2] = state[10];
	state[10] = temp;
	temp = state[6];
	state[6] = state[14];
	state[14] = temp;

	temp = state[3];
	state[3] = state[15];
	state[15] = state[11];
	state[11] = state[7];
	state[7] = temp;
}

// See "Efficient Software Implementation of AES on 32-bit platforms"
__device__ void MixColumns(unsigned char *state, unsigned char* GF_2, char* s) 
{
//[TODO] malloc!!!!!! is the criminal!!! CKJUNG, 18.10.26 
	memcpy(s, state, 4 * BLOCK_SIZE);
	int i;
#if 1
	for(i = 0; i < BLOCK_SIZE; i++) { // column
		unsigned char * x = (unsigned char*)&s[i*4];
		unsigned char * y = (unsigned char*)&state[i*4];
		y[0] = x[1] ^ x[2] ^ x[3];
		y[1] = x[0] ^ x[2] ^ x[3];
		y[2] = x[0] ^ x[1] ^ x[3];
		y[3] = x[0] ^ x[1] ^ x[2];
		x[0] = GF_2[x[0]];
		x[1] = GF_2[x[1]];
		x[2] = GF_2[x[2]];
		x[3] = GF_2[x[3]];
		y[0] ^= x[0] ^ x[1];
		y[1] ^= x[1] ^ x[2];
		y[2] ^= x[2] ^ x[3];
		y[3] ^= x[3] ^ x[0];
	}
#endif
} 

/**                                           
 * Initialize new context                      
 *                                             
 * @param context SHA1-Context                 
 */                                            
/*
 * Process extended block.
 */
__device__ void sha1_gpu_process (sha1_gpu_context *ctx, uint32_t W[80])
{
	uint32_t A, B, C, D, E;

	A = ctx->state[0];
	B = ctx->state[1];
	C = ctx->state[2];
	D = ctx->state[3];
	E = ctx->state[4];

#define P(a,b,c,d,e,x)\
{\
	e += S(a,5) + F(b,c,d) + K + x; b = S(b,30);\
}

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

	P( A, B, C, D, E, W[0]  );
	P( E, A, B, C, D, W[1]  );
	P( D, E, A, B, C, W[2]  );
	P( C, D, E, A, B, W[3]  );
	P( B, C, D, E, A, W[4]  );
	P( A, B, C, D, E, W[5]  );
	P( E, A, B, C, D, W[6]  );
	P( D, E, A, B, C, W[7]  );
	P( C, D, E, A, B, W[8]  );
	P( B, C, D, E, A, W[9]  );
	P( A, B, C, D, E, W[10] );
	P( E, A, B, C, D, W[11] );
	P( D, E, A, B, C, W[12] );
	P( C, D, E, A, B, W[13] );
	P( B, C, D, E, A, W[14] );
	P( A, B, C, D, E, W[15] );
	P( E, A, B, C, D, W[16] );
	P( D, E, A, B, C, W[17] );
	P( C, D, E, A, B, W[18] );
	P( B, C, D, E, A, W[19] );

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

	P( A, B, C, D, E, W[20] );
	P( E, A, B, C, D, W[21] );
	P( D, E, A, B, C, W[22] );
	P( C, D, E, A, B, W[23] );
	P( B, C, D, E, A, W[24] );
	P( A, B, C, D, E, W[25] ); // w[25] is the problem.
	P( E, A, B, C, D, W[26] );
	P( D, E, A, B, C, W[27] );
	P( C, D, E, A, B, W[28] );
	P( B, C, D, E, A, W[29] );
	P( A, B, C, D, E, W[30] );
	P( E, A, B, C, D, W[31] );
	P( D, E, A, B, C, W[32] );
	P( C, D, E, A, B, W[33] );
	P( B, C, D, E, A, W[34] );
	P( A, B, C, D, E, W[35] );
	P( E, A, B, C, D, W[36] );
	P( D, E, A, B, C, W[37] );
	P( C, D, E, A, B, W[38] );
	P( B, C, D, E, A, W[39] );


#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

	P( A, B, C, D, E, W[40] );
	P( E, A, B, C, D, W[41] );
	P( D, E, A, B, C, W[42] );
	P( C, D, E, A, B, W[43] );
	P( B, C, D, E, A, W[44] );
	P( A, B, C, D, E, W[45] );
	P( E, A, B, C, D, W[46] );
	P( D, E, A, B, C, W[47] );
	P( C, D, E, A, B, W[48] );
	P( B, C, D, E, A, W[49] );
	P( A, B, C, D, E, W[50] );
	P( E, A, B, C, D, W[51] );
	P( D, E, A, B, C, W[52] );
	P( C, D, E, A, B, W[53] );
	P( B, C, D, E, A, W[54] );
	P( A, B, C, D, E, W[55] );
	P( E, A, B, C, D, W[56] );
	P( D, E, A, B, C, W[57] );
	P( C, D, E, A, B, W[58] );
	P( B, C, D, E, A, W[59] );

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

	P( A, B, C, D, E, W[60] );
	P( E, A, B, C, D, W[61] );
	P( D, E, A, B, C, W[62] );
	P( C, D, E, A, B, W[63] );
	P( B, C, D, E, A, W[64] );
	P( A, B, C, D, E, W[65] );
	P( E, A, B, C, D, W[66] );
	P( D, E, A, B, C, W[67] );
	P( C, D, E, A, B, W[68] );
	P( B, C, D, E, A, W[69] );
	P( A, B, C, D, E, W[70] );
	P( E, A, B, C, D, W[71] );
	P( D, E, A, B, C, W[72] );
	P( C, D, E, A, B, W[73] );
	P( B, C, D, E, A, W[74] );
	P( A, B, C, D, E, W[75] );
	P( E, A, B, C, D, W[76] );
	P( D, E, A, B, C, W[77] );
	P( C, D, E, A, B, W[78] );
	P( B, C, D, E, A, W[79] );
#undef K
#undef F

	ctx->state[0] += A;
	ctx->state[1] += B;
	ctx->state[2] += C;
	ctx->state[3] += D;
	ctx->state[4] += E;
}

unsigned int SubWord(unsigned int w) {                                              
	unsigned int i = (sbox[(w >> 24) & 0xFF] << 24) | (sbox[(w >> 16) & 0xFF] << 16); 
	i |= (sbox[(w >> 8) & 0xFF] << 8) | sbox[w & 0xFF];                               
	return i;                                                                         
}                                                                                   

unsigned int RotWord(unsigned int w) {                                              
	unsigned char temp = (w >> 24) & 0xFF;                                            
	return ((w << 8) | temp);                                                         
}                                                                                   

void KeyExpansion(unsigned char* key, unsigned int* w) {
	unsigned int temp;
	int i = 0;
	
	for(i = 0; i < KEY_SIZE; i++) {
		w[i] = (key[4*i] << 24) | (key[4*i + 1] << 16) | (key[4*i + 2] << 8) | key[4*i + 3];
	}
	
	for(; i < BLOCK_SIZE * (NUM_ROUNDS + 1); i++) {
		temp = w[i - 1];
		if(i % KEY_SIZE == 0) {
			temp = SubWord(RotWord(temp)) ^ Rcon[i / KEY_SIZE];
		}
		w[i] = w[i - KEY_SIZE] ^ temp;
	}
}                                                                                                            

extern "C"
void initialize_ipsec(struct mempool **mempool, uint32_t *pkt_cnt)
{

	// CKJUNG, 18.10.25 [NF #2: IPSec] Setting initial_counter, key /////////////////////////

	unsigned char nounce[16];
	FILE* fnounce = fopen("./apps/lib/test.ctr", "rb");
	fread(&nounce, 1, 16, fnounce);
	fclose(fnounce);

	int num_keys = BLOCK_SIZE * (NUM_ROUNDS + 1);
	unsigned char key[16];
	unsigned int* expanded_key = (unsigned int*)malloc(num_keys * sizeof(int));
	FILE* fkey = fopen("./apps/lib/test.key", "rb");
	fread(&key, 1, 16, fkey);
	fclose(fkey);
	KeyExpansion(key, expanded_key);

	unsigned char *d_nounce;
	unsigned int *d_key;
	unsigned char *d_sbox;
	unsigned char *d_GF2;
	unsigned int *d_seq; // 20.02.02. CKJUNG


	printf("____[Initialize]__NF #2__IPSec__\n");
	
	ASSERTRT(cudaMalloc((void**)&d_nounce, 16*sizeof(unsigned char)));
	ASSERTRT(cudaMemset(d_nounce, 0, 16*sizeof(unsigned char)));
	ASSERTRT(cudaMalloc((void**)&d_key, num_keys*sizeof(unsigned int)));
	ASSERTRT(cudaMemset(d_key, 0, num_keys*sizeof(unsigned int)));
	ASSERTRT(cudaMalloc((void**)&d_sbox, 256*sizeof(unsigned char)));
	ASSERTRT(cudaMemset(d_sbox, 0, 256*sizeof(unsigned char)));
	ASSERTRT(cudaMalloc((void**)&d_GF2, 256*sizeof(unsigned char)));
	ASSERTRT(cudaMemset(d_GF2, 0, 256*sizeof(unsigned char)));
	
	ASSERTRT(cudaMalloc((void**)&d_seq, sizeof(unsigned int)));
	ASSERTRT(cudaMemset(d_seq, 0, sizeof(unsigned int)));
	
	cudaError_t nounce_err = cudaMemcpy(d_nounce, nounce, 16*sizeof(unsigned char), cudaMemcpyHostToDevice);
	cudaError_t key_err = cudaMemcpy(d_key, expanded_key, num_keys*sizeof(unsigned int), cudaMemcpyHostToDevice);
	cudaError_t sbox_err = cudaMemcpy(d_sbox, sbox, 256*sizeof(unsigned char), cudaMemcpyHostToDevice);
	cudaError_t GF2_err = cudaMemcpy(d_GF2, GF_2, 256*sizeof(unsigned char), cudaMemcpyHostToDevice);
	if(nounce_err != cudaSuccess || key_err != cudaSuccess || sbox_err != cudaSuccess || GF2_err != cudaSuccess)
	{
		START_RED
			printf("[Error] cudaMemcpy for \"nounce\" or \"key\" or \"sbox\" or \"GF2\" has failed.\n");
		END
	}else{
		START_GRN
			printf("[IPSec] Nounce, Expanded keys, SBOX, and GF2 are ready.\n");
		END
	}

	cudaStream_t cuda_stream3;
	ASSERT_CUDA(cudaStreamCreateWithFlags(&cuda_stream3,cudaStreamNonBlocking));
	
	printf("NF#2: IPsec\n");

	START_BLU
	printf("[IPSEC] # of Thread Blocks : %d, # of Threads : %d\n", NF_TB_NUM, NF_T_NUM);
	END

	/* 
	 * ipsec for 64B pkt
	 * 1 pkt needs 1 GPU threads.
	 * 512 x 1 = 512 threads. (OK)
	 * 384 threads per TB; 512 = 1 * 512; each TB manages 512 pkts; 128 * 1 = 512 Desc
	 */
	ipsec<<< NF_TB_NUM, NF_T_NUM, 0, cuda_stream3 >>> (mempool, pkt_cnt, d_nounce, d_key, d_sbox, d_GF2, d_seq); 

	START_GRN
	printf("[Done]____[Initialize]__NF #2__IPSec__\n");
	printf("[IPSEC] %s\n", cudaGetErrorName(cudaGetLastError()));
	END	

	free(expanded_key);
	// ~ CKJUNG /////////////////////////////////////////////////////////////////////////////
}

