/*
 * keccak.cu  Implementation of Keccak/SHA3 digest
 *
 * Date: 12 June 2019
 * Revision: 1
 *
 * This file is released into the Public Domain.
 */
 
 
extern "C"
{
    #include "keccak.cuh"
}

#define KECCAK_ROUND 24
#define KECCAK_STATE_SIZE 25
#define KECCAK_Q_SIZE 192

__constant__ uint64_t CUDA_KECCAK_CONSTS[24] = { 0x0000000000000001, 0x0000000000008082,
                                          0x800000000000808a, 0x8000000080008000, 0x000000000000808b, 0x0000000080000001, 0x8000000080008081,
                                          0x8000000000008009, 0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
                                          0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002,
                                          0x8000000000000080, 0x000000000000800a, 0x800000008000000a, 0x8000000080008081, 0x8000000000008080,
                                          0x0000000080000001, 0x8000000080008008 };

typedef struct {
    int64_t state[KECCAK_STATE_SIZE];
    uint8_t q[KECCAK_Q_SIZE];

} cuda_keccak_ctx_t;
typedef cuda_keccak_ctx_t CUDA_KECCAK_CTX;


__device__ int64_t cuda_keccak_MIN(int64_t a, int64_t b)
{
    if (a > b) return b;
    return a;
}

__device__ uint64_t cuda_keccak_UMIN(uint64_t a, uint64_t b)
{
    if (a > b) return b;
    return a;
}

__device__ uint64_t cuda_keccak_leuint64(void *in)
{
    uint64_t a;
    memcpy(&a, in, 8);
    return a;
}

__device__ __noinline__ void exact_and_reverse_hash_from_state(int64_t* state, uint8_t* out) {  //no inline hange nvcc build
    uint8_t* bytes;
    int index = 0;
    for (int i = 3; i >= 0; i--) {
        bytes = reinterpret_cast<uint8_t*>(&state[i]);
        for (int j = 7; j >= 0; j--) {
            out[index++] = bytes[j];
        }
    }
}


__device__ __forceinline__ unsigned long long asm_xor5(const unsigned long long a, const unsigned long long b, const unsigned long long c, const unsigned long long d, const unsigned long long e)
{
	unsigned long long result;
	asm("xor.b64 %0, %1, %2;" : "=l"(result) : "l"(d) ,"l"(e));
	asm("xor.b64 %0, %0, %1;" : "+l"(result) : "l"(c));
	asm("xor.b64 %0, %0, %1;" : "+l"(result) : "l"(b));
	asm("xor.b64 %0, %0, %1;" : "+l"(result) : "l"(a));
	return result;
}


__constant__ static const int piln[24] = {
    10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4, 
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1 
};

__constant__ static const int r[24] = {
    1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14, 
    27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
};

__device__ __forceinline__ uint64_t asm_cuda_keccak_ROTL64(const uint64_t x, const int offset) {
	uint64_t res;
	asm("{ // ROTL64 \n\t"
		".reg .u32 tl,th,vl,vh;\n\t"
		".reg .pred p;\n\t"
		"mov.b64 {tl,th}, %1;\n\t"
		"shf.l.wrap.b32 vl, tl, th, %2;\n\t"
		"shf.l.wrap.b32 vh, th, tl, %2;\n\t"
		"setp.lt.u32 p, %2, 32;\n\t"
		"@!p mov.b64 %0, {vl,vh};\n\t"
		"@p  mov.b64 %0, {vh,vl};\n\t"
	"}\n" : "=l"(res) : "l"(x) , "r"(offset)
	);
	return res;
}

__device__ void keccakf(uint64_t *state){
    int i, j;
    uint64_t temp, C[5];

    for (int round = 0; round < 24; round++) {
        // Theta
        for (i = 0; i < 5; i++) {
            C[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        }

        for (i = 0; i < 5; i++) {
            temp = C[(i + 4) % 5] ^ asm_cuda_keccak_ROTL64(C[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5) {
                state[j + i] ^= temp;
            }
        }

        // Rho Pi
        temp = state[1];
        for (i = 0; i < 24; i++) {
            j = piln[i];
            C[0] = state[j];
            state[j] = asm_cuda_keccak_ROTL64(temp, r[i]);
            temp = C[0];
        }

        //  Chi
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++) {
                C[i] = state[j + i];
            }
            for (i = 0; i < 5; i++) {
                state[j + i] ^= (~C[(i + 1) % 5]) & C[(i + 2) % 5];
            }
        }

        //  Iota
        state[0] ^= CUDA_KECCAK_CONSTS[round];
    }
}

__device__ __forceinline__ static void cuda_keccak_permutations(int64_t* A)
{
    int64_t *a00 = A, *a01 = A + 1, *a02 = A + 2, *a03 = A + 3, *a04 = A + 4;
    int64_t *a05 = A + 5, *a06 = A + 6, *a07 = A + 7, *a08 = A + 8, *a09 = A + 9;
    int64_t *a10 = A + 10, *a11 = A + 11, *a12 = A + 12, *a13 = A + 13, *a14 = A + 14;
    int64_t *a15 = A + 15, *a16 = A + 16, *a17 = A + 17, *a18 = A + 18, *a19 = A + 19;
    int64_t *a20 = A + 20, *a21 = A + 21, *a22 = A + 22, *a23 = A + 23, *a24 = A + 24;
	
	int64_t c0;
	int64_t c1;
	int64_t c2;
	int64_t c3;
	int64_t c4;
	
	int64_t d0;
	int64_t d1;
	int64_t d2;
	int64_t d3;
	int64_t d4;
	
	#pragma unroll 24
    for (int i = 0; i < KECCAK_ROUND; i++) {

        /* Theta */
        /*
		c0 = *a00 ^ *a05 ^ *a10 ^ *a15 ^ *a20;
        c1 = *a01 ^ *a06 ^ *a11 ^ *a16 ^ *a21;
        c2 = *a02 ^ *a07 ^ *a12 ^ *a17 ^ *a22;
        c3 = *a03 ^ *a08 ^ *a13 ^ *a18 ^ *a23;
        c4 = *a04 ^ *a09 ^ *a14 ^ *a19 ^ *a24;
		*/
		c0 = asm_xor5(*a00, *a05, *a10, *a15, *a20);
		c1 = asm_xor5(*a01, *a06, *a11, *a16, *a21);
		c2 = asm_xor5(*a02, *a07, *a12, *a17, *a22);
		c3 = asm_xor5(*a03, *a08, *a13, *a18, *a23);
		c4 = asm_xor5(*a04, *a09, *a14, *a19, *a24);
		
        d1 = asm_cuda_keccak_ROTL64(c1, 1) ^ c4;
        d2 = asm_cuda_keccak_ROTL64(c2, 1) ^ c0;
        d3 = asm_cuda_keccak_ROTL64(c3, 1) ^ c1;
        d4 = asm_cuda_keccak_ROTL64(c4, 1) ^ c2;
        d0 = asm_cuda_keccak_ROTL64(c0, 1) ^ c3;

        *a00 ^= d1;
        *a05 ^= d1;
        *a10 ^= d1;
        *a15 ^= d1;
        *a20 ^= d1;
        *a01 ^= d2;
        *a06 ^= d2;
        *a11 ^= d2;
        *a16 ^= d2;
        *a21 ^= d2;
        *a02 ^= d3;
        *a07 ^= d3;
        *a12 ^= d3;
        *a17 ^= d3;
        *a22 ^= d3;
        *a03 ^= d4;
        *a08 ^= d4;
        *a13 ^= d4;
        *a18 ^= d4;
        *a23 ^= d4;
        *a04 ^= d0;
        *a09 ^= d0;
        *a14 ^= d0;
        *a19 ^= d0;
        *a24 ^= d0;

        /* Rho pi */
        c1 = asm_cuda_keccak_ROTL64(*a01, 1);
        *a01 = asm_cuda_keccak_ROTL64(*a06, 44);
        *a06 = asm_cuda_keccak_ROTL64(*a09, 20);
        *a09 = asm_cuda_keccak_ROTL64(*a22, 61);
        *a22 = asm_cuda_keccak_ROTL64(*a14, 39);
        *a14 = asm_cuda_keccak_ROTL64(*a20, 18);
        *a20 = asm_cuda_keccak_ROTL64(*a02, 62);
        *a02 = asm_cuda_keccak_ROTL64(*a12, 43);
        *a12 = asm_cuda_keccak_ROTL64(*a13, 25);
        *a13 = asm_cuda_keccak_ROTL64(*a19, 8);
        *a19 = asm_cuda_keccak_ROTL64(*a23, 56);
        *a23 = asm_cuda_keccak_ROTL64(*a15, 41);
        *a15 = asm_cuda_keccak_ROTL64(*a04, 27);
        *a04 = asm_cuda_keccak_ROTL64(*a24, 14);
        *a24 = asm_cuda_keccak_ROTL64(*a21, 2);
        *a21 = asm_cuda_keccak_ROTL64(*a08, 55);
        *a08 = asm_cuda_keccak_ROTL64(*a16, 45);
        *a16 = asm_cuda_keccak_ROTL64(*a05, 36);
        *a05 = asm_cuda_keccak_ROTL64(*a03, 28);
        *a03 = asm_cuda_keccak_ROTL64(*a18, 21);
        *a18 = asm_cuda_keccak_ROTL64(*a17, 15);
        *a17 = asm_cuda_keccak_ROTL64(*a11, 10);
        *a11 = asm_cuda_keccak_ROTL64(*a07, 6);
        *a07 = asm_cuda_keccak_ROTL64(*a10, 3);
        *a10 = c1;

        /* Chi */
        c0 = *a00 ^ (~*a01 & *a02);
        c1 = *a01 ^ (~*a02 & *a03);
        *a02 ^= ~*a03 & *a04;
        *a03 ^= ~*a04 & *a00;
        *a04 ^= ~*a00 & *a01;
        *a00 = c0;
        *a01 = c1;

        c0 = *a05 ^ (~*a06 & *a07);
        c1 = *a06 ^ (~*a07 & *a08);
        *a07 ^= ~*a08 & *a09;
        *a08 ^= ~*a09 & *a05;
        *a09 ^= ~*a05 & *a06;
        *a05 = c0;
        *a06 = c1;

        c0 = *a10 ^ (~*a11 & *a12);
        c1 = *a11 ^ (~*a12 & *a13);
        *a12 ^= ~*a13 & *a14;
        *a13 ^= ~*a14 & *a10;
        *a14 ^= ~*a10 & *a11;
        *a10 = c0;
        *a11 = c1;

        c0 = *a15 ^ (~*a16 & *a17);
        c1 = *a16 ^ (~*a17 & *a18);
        *a17 ^= ~*a18 & *a19;
        *a18 ^= ~*a19 & *a15;
        *a19 ^= ~*a15 & *a16;
        *a15 = c0;
        *a16 = c1;

        c0 = *a20 ^ (~*a21 & *a22);
        c1 = *a21 ^ (~*a22 & *a23);
        *a22 ^= ~*a23 & *a24;
        *a23 ^= ~*a24 & *a20;
        *a24 ^= ~*a20 & *a21;
        *a20 = c0;
        *a21 = c1;

        /* Iota */
        *a00 ^= CUDA_KECCAK_CONSTS[i];
    }
}

__noinline__ __device__ static bool hashbelowtarget(const uint64_t *const __restrict__ hash, const uint64_t *const __restrict__ target)
{
    if (hash[3] > target[3])//46
        return false;
    if (hash[3] < target[3])//46
        return true;
    if (hash[2] > target[2])//45
        return false;
    if (hash[2] < target[2])//45
        return true;

    if (hash[1] > target[1])//43
        return false;
    if (hash[1] < target[1])//43
        return true;
    if (hash[0] > target[0])//39
        return false;

    return true;
}

__device__ uint64_t *addUint256(const uint64_t *a, const uint64_t b)
{
    uint64_t *result = new uint64_t[4];//47
    uint64_t sum = a[0] + b;//10
    result[0] = sum;//10

    uint64_t carry = (sum < a[0]) ? 1 : 0;//12
    for (int i = 1; i < 4; i++)//13
    {
        sum = a[i] + carry;//16
        result[i] = sum;//14
        carry = (sum < a[i]) ? 1 : 0;//14
    }

    return result;
}

__device__ void reverseArray(unsigned char *array, int n) {
    for (int i = 0; i < n / 2; ++i) {
        unsigned char temp = array[i];
        array[i] = array[n - 1 - i];
        array[n - 1 - i] = temp;
    }
}


extern "C" __global__

  void kernel_lilypad_pow_debug(uint8_t* chanllenge, uint64_t* startNonce,  uint64_t* target, uint32_t n_batch, uint8_t* resNonce,  uint8_t *hash, uint8_t *pack)
{
    uint32_t thread = blockIdx.x * blockDim.x + threadIdx.x; //4
    if (thread >= n_batch) {//36
        return;
    }

       //increase nonce
    uint8_t* nonce = (uint8_t*)addUint256(startNonce, thread);//35

  
    int64_t state[KECCAK_STATE_SIZE];
    uint8_t q[KECCAK_Q_SIZE];  
    memset(q, 0, 192);  
    memset(state, 0, 200);

    memcpy(q , chanllenge , 32);  //copy challenge
    for (int i = 32; i < 64; i++)//reverse copy nonce
    {
        q[i] = nonce[63-i];
    }
   
    {//pad
        //0-7 uint64 = 64 bytes
        uint64_t offset = 0;
        for (int i = 0; i < 8; ++i) {
            state[i] ^= cuda_keccak_leuint64(q + offset);
            offset += 8;
        }

        //64th bytes
        q[64] |= (1L << (512 & 7)); 
        uint64_t mask = (1L << 1) - 1;//17
        state[8] ^= cuda_keccak_leuint64(q + 64) & mask;//16

        //16 byte, 1024 bytes
        state[16] ^= 9223372036854775808ULL;/* 1 << 63 */   //9
    }
    

    keccakf((uint64_t*)state);//8

    uint8_t out[32];
    exact_and_reverse_hash_from_state(state, out);//58
    
    if (hashbelowtarget((uint64_t*)out, target)) {//49
        reverseArray(out, 32);//18
        memcpy(hash, out, 32);
      //  memcpy(pack, in, 64);
        reverseArray(nonce,32);
        memcpy(resNonce, nonce, 32);
    } 

    delete nonce;//45
}
