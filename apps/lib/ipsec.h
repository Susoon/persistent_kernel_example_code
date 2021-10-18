#ifndef __IPSEC_H_
#define __IPSEC_H_
// CKJUNG
#include <stdint.h>
#include "util.cu.h"
#include "memory.cu.h"
#include "log.h"
#include "sbox.h"
#include "gf_tables.h"
#include "pkt_data.h"
#include <linux/if_ether.h>
#include <linux/ip.h>      
#include <linux/udp.h>
#include <linux/in.h>

#define NUM_TURN_ipsec 2

// CKJUNG, 18.10.31, SHA1                                                    
#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))  
#if defined (BYTE_ORDER) && defined(BIG_ENDIAN) && (BYTE_ORDER == BIG_ENDIAN)
#define WORDS_BIGENDIAN 1                                                    
#endif                                                                       

#ifdef _BIG_ENDIAN                                                           
#define WORDS_BIGENDIAN 1                                                    
#endif                                                                       


// CKJUNG, 18.10.31
#define HTONS32(n) do { uint8_t swap_tmp; int j; for(j = 0; j < 2; j++) { \
	swap_tmp = *(((uint8_t*)&n) + j); \
	*(((uint8_t*)&n) + j) = *(((uint8_t*)&n) + 3 - j); \
	*(((uint8_t*)&n) + 3 - j) = swap_tmp; \
	} \
	} while(0)
	

// CKJUNG, 18.09.19
#define BLOCK_SIZE 4    // Nb Block size (as per standard)
#define KEY_SIZE 4  // Nk Key size (AES-128)              
#define NUM_ROUNDS 10   // Nr Number of rounds (AES-128)


__device__ void AddRoundKey(unsigned char *state, unsigned *w);
__device__ void SubBytes(unsigned char *state, unsigned char* sbox);
__device__ void ShiftRows(unsigned char *state);
__device__ void MixColumns(unsigned char *state, unsigned char* GF_2, char* s);
__device__ int hex2dec(char * a);

// CKJUNG, 18.10.31.
struct esphdr {
	uint32_t spi;
	uint32_t seq;
};


/* public api for steve reid's public domain SHA-1 implementation */
/* this file is in the public domain */                             

/** SHA-1 Context */                                                
typedef struct {                                                    
	uint32_t state[5];                                              
	/**< Context state */                                           
	uint32_t count[2];                                              
	/**< Counter       */                                           
	uint8_t buffer[64]; /**< SHA-1 buffer  */                       
} SHA1_CTX;                                                         


/** SHA-1 Context (OpenSSL compat) */             
typedef SHA1_CTX SHA_CTX;                         
                                                  
/** SHA-1 Digest size in bytes */                 
#define SHA1_DIGEST_SIZE 20                       
/** SHA-1 Digest size in bytes (OpenSSL compat) */
#define SHA_DIGEST_LENGTH SHA1_DIGEST_SIZE        


__device__ void SHA1_Transform(uint32_t state[5], const uint8_t buffer[64]);
__device__ void SHA1_Init(SHA1_CTX *context);
__device__ void SHA1_Update(SHA1_CTX *context, const void *p, size_t len);
__device__ void SHA1_Final(unsigned char digest[SHA1_DIGEST_SIZE], SHA1_CTX *context);

#define SHA_BLOCKSIZE   (64)

__device__ void hmac_sha1(unsigned char *k,  /* secret key */                 
		int lk,       /* length of the key in bytes */          
		unsigned char *d,  /* data */                              
		int ld,       /* length of data in bytes */             
		unsigned char *out,      /* output buffer, at least "t" bytes */ 
		int *t, 
		SHA_CTX *ictx, 
		SHA_CTX *octx,
		unsigned char* isha,
		unsigned char* osha,
		unsigned char* key,
		unsigned char* buf);

// CKJUNG, 18. 11. 09 SHA-1
typedef union{
	unsigned char c_state[24];
	uint32_t state[6]; // For divide by 3. (5 --> 6)
} sha1_gpu_context;

#define GET_UINT32_BE(n,b,i)\
{\
	(n) = ( (unsigned long) (b)[(i) ] << 24 )\
	| ( (unsigned long) (b)[(i) + 1] << 16 )\
	| ( (unsigned long) (b)[(i) + 2] <<  8 )\
	| ( (unsigned long) (b)[(i) + 3]       );\
}

#define PUT_UINT32_BE(n,b,i)\
{\
	(b)[(i)    ] = (unsigned char) ( (n) >> 24 ); \
	(b)[(i) + 1] = (unsigned char) ( (n) >> 16 ); \
	(b)[(i) + 2] = (unsigned char) ( (n) >>  8 ); \
	(b)[(i) + 3] = (unsigned char) ( (n)       ); \
}                                                  

// Same with "rol" in openssl source. 
#define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))


__device__ void sha1_gpu_process (sha1_gpu_context *ctx, uint32_t W[80]);
__device__ void sha1_kernel_global(unsigned char *data, sha1_gpu_context *ctx, uint32_t *extended, int len);

__global__ void ipsec(struct pkt_buf *p_buf, int* pkt_cnt, unsigned int* ctr, unsigned char* d_nounce, unsigned int* d_key, unsigned char* d_sbox, unsigned char* d_GF2);


unsigned int SubWord(unsigned int w);
unsigned int RotWord(unsigned int w);

static const unsigned int Rcon[] = {                                                
	0x00000000, 0x01000000, 0x02000000, 0x04000000,                                   
	0x08000000, 0x10000000, 0x20000000, 0x40000000,                                   
	0x80000000, 0x1B000000, 0x36000000,                                               
	// more than 10 will not be used for 128 bit blocks                               
};                                                                                  


void KeyExpansion(unsigned char* key, unsigned int* w);

/* blk0() and blk() perform the initial expand. */                                                                
/* I got the idea of expanding during the round function from SSLeay */                                           
/* FIXME: can we do this in an endian-proof way? */                                                               
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xff00ff00) |(rol(block->l[i],8)&0x00ff00ff))                 

#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] ^block->l[(i+2)&15]^block->l[i&15],1))


/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */                                               
#define R0(v, w, x, y, z, i) z+=((w&(x^y))^y)+blk0(i)+0x5a827999+rol(v,5);w=rol(w,30);                            
#define R1(v, w, x, y, z, i) z+=((w&(x^y))^y)+blk(i)+0x5a827999+rol(v,5);w=rol(w,30);                             
#define R2(v, w, x, y, z, i) z+=(w^x^y)+blk(i)+0x6ed9eba1+rol(v,5);w=rol(w,30);                                   
#define R3(v, w, x, y, z, i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8f1bbcdc+rol(v,5);w=rol(w,30);                         
#define R4(v, w, x, y, z, i) z+=(w^x^y)+blk(i)+0xca62c1d6+rol(v,5);w=rol(w,30);                                   
extern "C"
void initialize_ipsec(struct mempool **mempool, uint32_t *pkt_cnt);

#endif /* __IPSEC_H_ */
