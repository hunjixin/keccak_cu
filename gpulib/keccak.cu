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
__device__ uint64_t rotate(uint64_t val, unsigned n) { return val << n | val >> (64 - n); }
   
// Array of indices and rotation values for P and Pi phases.
__constant__ uint8_t g_ppi_aux[25][2] = {
    {0, 0},   {6, 44},  {12, 43}, {18, 21}, {24, 14},
    {3, 28},  {9, 20},  {10, 3},  {16, 45}, {22, 61},
    {1, 1},   {7, 6},   {13, 25}, {19, 8},  {20, 18},
    {4, 27},  {5, 36},  {11, 10}, {17, 15}, {23, 56},
    {2, 62},  {8, 55},  {14, 39}, {15, 41}, {21, 2}
};

// Array of indices for ksi phase.
__constant__ uint8_t g_ksi_aux[25][2] = {
    {1, 2},   {2, 3},   {3, 4},   {4, 0},   {0, 1},
    {6, 7},   {7, 8},   {8, 9},   {9, 5},   {5, 6},
    {11, 12}, {12, 13}, {13, 14}, {14, 10}, {10, 11},
    {16, 17}, {17, 18}, {18, 19}, {19, 15}, {15, 16},
    {21, 22}, {22, 23}, {23, 24}, {24, 20}, {20, 21}
};

__constant__ uint64_t g_iota_aux[24] = {
    0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L, 0x000000000000808bL,
    0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL, 0x0000000000000088L,
    0x0000000080008009L, 0x000000008000000aL, 0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
    0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
    0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
};

__device__  static void cuda_keccak_permutations(uint64_t *A, uint64_t *C,  const int threadIndexInWrap)
{
    printf("%d\n", threadIndexInWrap);
    size_t s = threadIndexInWrap % 5;

    #pragma unroll
    for (int round_idx = 0; round_idx < 24; ++round_idx)
    {
        // Thetta phase.
        C[threadIndexInWrap] = A[s] ^ A[s + 5] ^ A[s + 10] ^ A[s + 15] ^ A[s + 20];
        A[threadIndexInWrap] ^= C[s + 5 - 1] ^ rotate(C[s + 1], 1);

        // P and Pi combined phases.
        C[threadIndexInWrap] = rotate(A[g_ppi_aux[threadIndexInWrap][0]], g_ppi_aux[threadIndexInWrap][1]);

        // Ksi phase.
        A[threadIndexInWrap] = C[threadIndexInWrap] ^ (~C[g_ksi_aux[threadIndexInWrap][0]] & C[g_ksi_aux[threadIndexInWrap][1]]);

        // Iota phase.
        A[threadIndexInWrap] ^= threadIndexInWrap == 0 ? g_iota_aux[round_idx] : 0;
    }
}

__device__ __forceinline__ static bool hashbelowtarget(const uint64_t *const __restrict__ hash, const uint64_t *const __restrict__ target)
{
    if (hash[3] > target[3])
        return false;
    if (hash[3] < target[3])
        return true;
    if (hash[2] > target[2])
        return false;
    if (hash[2] < target[2])
        return true;

    if (hash[1] > target[1])
        return false;
    if (hash[1] < target[1])
        return true;
    if (hash[0] > target[0])
        return false;

    return true;
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

__device__ void reverseArray(unsigned char *array, int n)
{
    for (int i = 0; i < n / 2; ++i)
    {
        unsigned char temp = array[i];
        array[i] = array[n - 1 - i];
        array[n - 1 - i] = temp;
    }
}


#define WRAP_IN_BLOCK 32  // equal to block_size/32

//1024 32
//512  16
#define WRAP_IN_BLOCK 32  // equal to block_size/32

extern "C" __global__ __launch_bounds__(1024) void kernel_lilypad_pow_debug(
    const uint8_t *__restrict__ challenge,
    const uint64_t *__restrict__ startNonce,
    const uint64_t *__restrict__ target,
    const uint32_t n_batch,
    const uint32_t hashPerThread, uint8_t *resNonce, uint8_t *hash, uint8_t *pack)
{
    int thread = blockIdx.x * blockDim.x + threadIdx.x;
    if (thread >= n_batch) // batch must equal with grid*block
    {
        return;
    }

    int wrapInOneLaunch = thread / 32;
    int threadIndexInWrap = thread % 32;     // index in wrap
    if (threadIndexInWrap >= 25)             // abort 26-32 thread
    {
        return;
    }

    int wrapIndexInBlock = threadIdx.x / 32; // one wrap one worker, 25/32 usages
   // printf("wrapIndexInBlock %d\n",  wrapIndexInBlock);
   // printf("threadIndexInWrap %d\n",  threadIndexInWrap);

    __shared__ uint64_t stateInBlock[WRAP_IN_BLOCK][KECCAK_STATE_SIZE];
    __shared__ uint64_t cInBlock[WRAP_IN_BLOCK][25];

    uint64_t *state = stateInBlock[wrapIndexInBlock];
    uint64_t *C = cInBlock[wrapIndexInBlock];

    C[threadIndexInWrap] = 0;
    // printf("C[0] %d\n",  C[1]);

    __syncwarp();
    int nonceOffset = wrapInOneLaunch * hashPerThread;
    int endNonceOffset = (wrapInOneLaunch + 1) * hashPerThread;
    for (; nonceOffset < endNonceOffset; nonceOffset++)
    {
        uint8_t cuda_pack[64];
        uint8_t *nonce;

        state[threadIndexInWrap] = 0;
        if (threadIndexInWrap == 0)
        {
            // increase nonce
            nonce = (uint8_t *)addUint256(startNonce, nonceOffset);
            memcpy(state, challenge, 32);    // Copy challenge into state
            memcpy(state + 4, nonce, 32);    // Copy nonce into state starting from index 4

          memcpy(cuda_pack, state, 64);

            state[8] ^= 1;
            state[16] ^= 9223372036854775808ULL;
        }

        cuda_keccak_permutations(state, C, threadIndexInWrap);

        if (threadIndexInWrap == 0)
        {

            uint8_t out[32];
            uint8_t *state_bytes = reinterpret_cast<uint8_t *>(state);
#pragma unroll 32
            for (int i = 0; i < 32; i++)
            {
                out[i] = state_bytes[31 - i];
            }

            if (hashbelowtarget((uint64_t *)out, target))
            {
                reverseArray(out, 32);
               memcpy(hash, out, 32);
               memcpy(pack, cuda_pack, 64);
                memcpy(resNonce, nonce, 32);
            }

            delete nonce; // 45
        }
    }
}
