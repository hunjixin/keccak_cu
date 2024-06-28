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


typedef union
{
	uint2		uint2;
	uint64_t	uint64;
	uint8_t		uint8[8];
} nonce_t;

__constant__ uint64_t d_midstate[25];
__constant__ uint64_t d_target[1];

__device__ __forceinline__ nonce_t bswap_64(nonce_t const input)
{
	nonce_t output;
	asm("{"
		"  prmt.b32 %0, %3, 0, 0x0123;"
		"  prmt.b32 %1, %2, 0, 0x0123;"
		"}" : "=r"(output.uint2.x), "=r"(output.uint2.y) : "r"(input.uint2.x), "r"(input.uint2.y));
	return output;
}

__device__ __forceinline__ nonce_t xor5(nonce_t const a, nonce_t const b, nonce_t const c, nonce_t const d, nonce_t const e)
{
	nonce_t output;
#if __CUDA_ARCH__ >= 500
	asm("{"
		"  lop3.b32 %0, %2, %4, %6, 0x96;"
		"  lop3.b32 %1, %3, %5, %7, 0x96;"
		"  lop3.b32 %0, %0, %8, %10, 0x96;"
		"  lop3.b32 %1, %1, %9, %11, 0x96;"
		"}" : "=r"(output.uint2.x), "=r"(output.uint2.y)
		: "r"(a.uint2.x), "r"(a.uint2.y), "r"(b.uint2.x), "r"(b.uint2.y), "r"(c.uint2.x), "r"(c.uint2.y), "r"(d.uint2.x), "r"(d.uint2.y), "r"(e.uint2.x), "r"(e.uint2.y));
#else
	asm("{"
		"  xor.b64 %0, %1, %2;"
		"  xor.b64 %0, %0, %3;"
		"  xor.b64 %0, %0, %4;"
		"  xor.b64 %0, %0, %5;"
		"}" : "=l"(output.uint64) : "l"(a.uint64), "l"(b.uint64), "l"(c.uint64), "l"(d.uint64), "l"(e.uint64));
#endif
	return output;
}

__device__ __forceinline__ nonce_t xor3(nonce_t const a, nonce_t const b, nonce_t const c)
{
	nonce_t output;
#if __CUDA_ARCH__ >= 500
	asm("{"
		"  lop3.b32 %0, %2, %4, %6, 0x96;"
		"  lop3.b32 %1, %3, %5, %7, 0x96;"
		"}" : "=r"(output.uint2.x), "=r"(output.uint2.y)
		: "r"(a.uint2.x), "r"(a.uint2.y), "r"(b.uint2.x), "r"(b.uint2.y), "r"(c.uint2.x), "r"(c.uint2.y));
#else
	asm("{"
		"  xor.b64 %0, %1, %2;"
		"  xor.b64 %0, %0, %3;"
		"}" : "=l"(output.uint64) : "l"(a.uint64), "l"(b.uint64), "l"(c.uint64));
#endif
	return output;
}

__device__ __forceinline__ nonce_t chi(nonce_t const a, nonce_t const b, nonce_t const c)
{
	nonce_t output;
#if __CUDA_ARCH__ >= 500
	asm("{"
		"  lop3.b32 %0, %2, %4, %6, 0xD2;"
		"  lop3.b32 %1, %3, %5, %7, 0xD2;"
		"}" : "=r"(output.uint2.x), "=r"(output.uint2.y)
		: "r"(a.uint2.x), "r"(a.uint2.y), "r"(b.uint2.x), "r"(b.uint2.y), "r"(c.uint2.x), "r"(c.uint2.y));
#else
	output.uint64 = a.uint64 ^ ((~b.uint64) & c.uint64);
#endif
	return output;
}

__device__ __forceinline__ nonce_t rotl(nonce_t input, uint32_t const offset)
{
#if __CUDA_ARCH__ >= 320
	asm("{"
		"  .reg .b32 tmp;"
		"  shf.l.wrap.b32 tmp, %1, %0, %2;"
		"  shf.l.wrap.b32 %1, %0, %1, %2;"
		"  mov.b32 %0, tmp;"
		"}" : "+r"(input.uint2.x), "+r"(input.uint2.y) : "r"(offset));
#else
	input.uint64 = (input.uint64 << offset) ^ (input.uint64 >> (64u - offset));
#endif
	return input;
}

__device__ __forceinline__ nonce_t rotr(nonce_t input, uint32_t const offset)
{
#if __CUDA_ARCH__ >= 320
	asm("{"
		"  .reg .b32 tmp;"
		"  shf.r.wrap.b32 tmp, %0, %1, %2;"
		"  shf.r.wrap.b32 %1, %1, %0, %2;"
		"  mov.b32 %0, tmp;"
		"}" : "+r"(input.uint2.x), "+r"(input.uint2.y) : "r"(offset));
#else
	input.uint64 = (input.uint64 >> offset) ^ (input.uint64 << (64u - offset));
#endif
	return input;
}

__constant__ static uint64_t const Keccak_f1600_RC[24] =
{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
	0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
	0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
	0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
	0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
	0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

__device__ __forceinline__ static void cuda_keccak_permutations(nonce_t *state)
{
    nonce_t  C[5], D[5];
#if __CUDA_ARCH__ >= 350
#	pragma unroll
#endif
	for (int i{ 0 }; i < KECCAK_ROUND; ++i)
	{
		C[1] = xor5(state[0], state[5], state[10], state[15], state[20]);
		C[2] = xor5(state[1], state[6], state[11], state[16], state[21]);
		C[3] = xor5(state[2], state[7], state[12], state[17], state[22]);
		C[4] = xor5(state[3], state[8], state[13], state[18], state[23]);
		C[0] = xor5(state[4], state[9], state[14], state[19], state[24]);

#if __CUDA_ARCH__ >= 350
		D[0] = rotl(C[2], 1);
		state[0] = xor3(state[0], D[0], C[0]);
		state[5] = xor3(state[5], D[0], C[0]);
		state[10] = xor3(state[10], D[0], C[0]);
		state[15] = xor3(state[15], D[0], C[0]);
		state[20] = xor3(state[20], D[0], C[0]);

		D[1] = rotl(C[3], 1);
		state[1] = xor3(state[1], D[1], C[1]);
		state[6] = xor3(state[6], D[1], C[1]);
		state[11] = xor3(state[11], D[1], C[1]);
		state[16] = xor3(state[16], D[1], C[1]);
		state[21] = xor3(state[21], D[1], C[1]);

		D[2] = rotl(C[4], 1);
		state[2] = xor3(state[2], D[2], C[2]);
		state[7] = xor3(state[7], D[2], C[2]);
		state[12] = xor3(state[12], D[2], C[2]);
		state[17] = xor3(state[17], D[2], C[2]);
		state[22] = xor3(state[22], D[2], C[2]);

		D[3] = rotl(C[0], 1);
		state[3] = xor3(state[3], D[3], C[3]);
		state[8] = xor3(state[8], D[3], C[3]);
		state[13] = xor3(state[13], D[3], C[3]);
		state[18] = xor3(state[18], D[3], C[3]);
		state[23] = xor3(state[23], D[3], C[3]);

		D[4] = rotl(C[1], 1);
		state[4] = xor3(state[4], D[4], C[4]);
		state[9] = xor3(state[9], D[4], C[4]);
		state[14] = xor3(state[14], D[4], C[4]);
		state[19] = xor3(state[19], D[4], C[4]);
		state[24] = xor3(state[24], D[4], C[4]);
#else
		for (int x{ 0 }; x < 5; ++x)
		{
			D[x].uint64 = rotl(C[(x + 2) % 5], 1).uint64 ^ C[x].uint64;
			state[x].uint64 = state[x].uint64 ^ D[x].uint64;
			state[x + 5].uint64 = state[x + 5].uint64 ^ D[x].uint64;
			state[x + 10].uint64 = state[x + 10].uint64 ^ D[x].uint64;
			state[x + 15].uint64 = state[x + 15].uint64 ^ D[x].uint64;
			state[x + 20].uint64 = state[x + 20].uint64 ^ D[x].uint64;
		}
#endif

		C[0] = state[1];
		state[1] = rotr(state[6], 20);
		state[6] = rotl(state[9], 20);
		state[9] = rotr(state[22], 3);
		state[22] = rotr(state[14], 25);
		state[14] = rotl(state[20], 18);
		state[20] = rotr(state[2], 2);
		state[2] = rotr(state[12], 21);
		state[12] = rotl(state[13], 25);
		state[13] = rotl(state[19], 8);
		state[19] = rotr(state[23], 8);
		state[23] = rotr(state[15], 23);
		state[15] = rotl(state[4], 27);
		state[4] = rotl(state[24], 14);
		state[24] = rotl(state[21], 2);
		state[21] = rotr(state[8], 9);
		state[8] = rotr(state[16], 19);
		state[16] = rotr(state[5], 28);
		state[5] = rotl(state[3], 28);
		state[3] = rotl(state[18], 21);
		state[18] = rotl(state[17], 15);
		state[17] = rotl(state[11], 10);
		state[11] = rotl(state[7], 6);
		state[7] = rotl(state[10], 3);
		state[10] = rotl(C[0], 1);

#if __CUDA_ARCH__ >= 350
#	pragma unroll
#endif
		for (int x{ 0 }; x < 25; x += 5)
		{
			C[0] = state[x];
			C[1] = state[x + 1];
			C[2] = state[x + 2];
			C[3] = state[x + 3];
			C[4] = state[x + 4];
			state[x] = chi(C[0], C[1], C[2]);
			state[x + 1] = chi(C[1], C[2], C[3]);
			state[x + 2] = chi(C[2], C[3], C[4]);
			state[x + 3] = chi(C[3], C[4], C[0]);
			state[x + 4] = chi(C[4], C[0], C[1]);
		}

		state[0].uint64 = state[0].uint64 ^ Keccak_f1600_RC[i];

	//	printf("Round %d\n", i);
	//	for (int j = 0; j < 25; j++) {
	//		printf("	Element %d: %llu\n", j, state[i].uint64);
	//	}

	}

}




__constant__ uint64_t CUDA_KECCAK_CONSTS[24] = {0x0000000000000001, 0x0000000000008082,
                                                0x800000000000808a, 0x8000000080008000, 0x000000000000808b, 0x0000000080000001, 0x8000000080008081,
                                                0x8000000000008009, 0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
                                                0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002,
                                                0x8000000000000080, 0x000000000000800a, 0x800000008000000a, 0x8000000080008081, 0x8000000000008080,
                                                0x0000000080000001, 0x8000000080008008};

__device__ __forceinline__ uint64_t asm_cuda_keccak_ROTL64(const uint64_t x, const int offset)
{
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
        "}\n" : "=l"(res) : "l"(x), "r"(offset));
    return res;
}

__device__ __forceinline__ static void cuda_keccak_permutations_old(uint64_t *A)
{
    uint64_t *a00 = A, *a01 = A + 1, *a02 = A + 2, *a03 = A + 3, *a04 = A + 4;
    uint64_t *a05 = A + 5, *a06 = A + 6, *a07 = A + 7, *a08 = A + 8, *a09 = A + 9;
    uint64_t *a10 = A + 10, *a11 = A + 11, *a12 = A + 12, *a13 = A + 13, *a14 = A + 14;
    uint64_t *a15 = A + 15, *a16 = A + 16, *a17 = A + 17, *a18 = A + 18, *a19 = A + 19;
    uint64_t *a20 = A + 20, *a21 = A + 21, *a22 = A + 22, *a23 = A + 23, *a24 = A + 24;

    for (int i = 0; i < KECCAK_ROUND; i++)
    {

        /* Theta */
        uint64_t c0 = *a00 ^ *a05 ^ *a10 ^ *a15 ^ *a20;
        uint64_t c1 = *a01 ^ *a06 ^ *a11 ^ *a16 ^ *a21;
        uint64_t c2 = *a02 ^ *a07 ^ *a12 ^ *a17 ^ *a22;
        uint64_t c3 = *a03 ^ *a08 ^ *a13 ^ *a18 ^ *a23;
        uint64_t c4 = *a04 ^ *a09 ^ *a14 ^ *a19 ^ *a24;

        int64_t d1 = asm_cuda_keccak_ROTL64(c1, 1) ^ c4;
        int64_t d2 = asm_cuda_keccak_ROTL64(c2, 1) ^ c0;
        int64_t d3 = asm_cuda_keccak_ROTL64(c3, 1) ^ c1;
        int64_t d4 = asm_cuda_keccak_ROTL64(c4, 1) ^ c2;
        int64_t d0 = asm_cuda_keccak_ROTL64(c0, 1) ^ c3;

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

        /* Chi * a ^ (~b) & c*/
        c0 = *a00 ^ (~*a01 & *a02); // use int2 vector this can be opt to 2 lop.b32 instruction
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
		printf("Round %d\n", i);
		for (int j = 0; j < 25; j++) {
			printf("	Element %d: %llu\n", j, (unsigned long long)A[i]);
		}

    }
}



__noinline__ __device__ static bool hashbelowtarget(const uint8_t *const __restrict__ hash, const uint8_t *const __restrict__ target)
{
    for (int i = 0; i < 32; i++)
    {
        if (hash[i] < target[i])
        {
            return true;
        }
        else if (hash[i] > target[i])
        {
            return false;
        }
    }
    return false;
}

__device__ uint64_t *addUint256(const uint64_t *a, const uint64_t b)
{
    uint64_t *result = new uint64_t[4];
    uint64_t sum = a[0] + b;
    result[0] = sum;

    uint64_t carry = (sum < a[0]) ? 1 : 0;
    for (int i = 1; i < 4; i++)
    {
        sum = a[i] + carry;
        result[i] = sum;
        carry = (sum < a[i]) ? 1 : 0;
    }

    return result;
}

#define THREAD_NUMBBER 256

extern "C" __global__ __launch_bounds__(THREAD_NUMBBER) void kernel_lilypad_pow(
    const uint8_t *__restrict__ challenge,
    const uint64_t *__restrict__ startNonce,
    const uint8_t *__restrict__ target,
    const uint32_t n_batch,
    const uint32_t hashPerThread, uint8_t *resNonce)
{
     uint32_t thread = blockIdx.x * blockDim.x + threadIdx.x;
    if (thread >= n_batch)
    {
        return;
    }
	if (threadIdx.x >=THREAD_NUMBBER) {
		return;
	}

   __shared__ nonce_t states[THREAD_NUMBBER][KECCAK_STATE_SIZE];
    for (int i = thread * hashPerThread; i < (thread + 1) * hashPerThread; i++)
    {
        // increase nonce
        uint8_t *nonce = (uint8_t *)addUint256(startNonce, i);
		nonce_t* state = states[threadIdx.x];

        memset(state, 0, 200);

        memcpy(state, challenge, 32); // Copy challenge into state
        memcpy(state + 4, nonce, 32); // Copy nonce into state starting from index 4

        state[8].uint64 ^= 1;
        state[16].uint64 ^= 9223372036854775808ULL;

        cuda_keccak_permutations((nonce_t*)(state));

        uint8_t *state_bytes = reinterpret_cast<uint8_t *>(state);
        if (hashbelowtarget(state->uint8, target))
        {
            memcpy(resNonce, nonce, 32);
        }

        delete nonce; // 45
    }
}


extern "C" __global__ __launch_bounds__(THREAD_NUMBBER) void kernel_lilypad_pow_debug(
    const uint8_t *__restrict__ challenge,
    const uint64_t *__restrict__ startNonce,
    const uint8_t *__restrict__ target,
    const uint32_t n_batch,
    const uint32_t hashPerThread, uint8_t *resNonce, uint8_t *hash, uint8_t *pack)
{
    uint32_t thread = blockIdx.x * blockDim.x + threadIdx.x;
    if (thread >= n_batch)
    {
        return;
    }
	if (threadIdx.x >=THREAD_NUMBBER) {
		return;
	}
   	__shared__ nonce_t states[THREAD_NUMBBER][KECCAK_STATE_SIZE];
    for (int i = thread * hashPerThread; i < (thread + 1) * hashPerThread; i++)
    {
        // increase nonce
        uint8_t *nonce = (uint8_t *)addUint256(startNonce, i);
		nonce_t* state = states[threadIdx.x];

        memset(state, 0, 200);

        memcpy(state, challenge, 32); // Copy challenge into state
        memcpy(state + 4, nonce, 32); // Copy nonce into state starting from index 4

        uint8_t cuda_pack[64];
        memcpy(cuda_pack, state, 64);

        state[8].uint64 ^= 1;
        state[16].uint64 ^= 9223372036854775808ULL;

        cuda_keccak_permutations((nonce_t*)(state));

        uint8_t *state_bytes = reinterpret_cast<uint8_t *>(state);
        if (hashbelowtarget(state->uint8, target))
        {
            memcpy(hash, state_bytes, 32);
            memcpy(pack, cuda_pack, 64);
            memcpy(resNonce, nonce, 32);
        }

        delete nonce; // 45
    }
}
