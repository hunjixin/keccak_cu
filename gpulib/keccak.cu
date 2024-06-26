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


#define ROUNDS 24
#define OFFSET 63
#define R64(a, b, c) (((a) << b) ^ ((a) >> c)) /* works on the GPU also for \
                                                  b = 64 or c = 64 */
__constant__ uint64_t rc[5][ROUNDS] = {
    {0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
     0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
     0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
     0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
     0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
     0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
     0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
     0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL},
    {0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL,
     0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL,
     0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL},
    {0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL,
     0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL,
     0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL},
    {0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL,
     0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL,
     0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL},
    {0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL,
     0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL,
     0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL}};

/* Rho-Offsets. Note that for each entry pair their respective sum is 64.
   Only the first entry of each pair is a rho-offset. The second part is
   used in the R64 macros. */
__constant__ int ro[25][2] = {
    /*y=0*/ /*y=1*/ /*y=2*/ /*y=3*/ /*y=4*/
    /*x=0*/ {0, 64}, /*x=1*/ {44, 20}, /*x=2*/ {43, 21}, /*x=3*/ {21, 43}, /*x=4*/ {14, 50},
    /*x=1*/ {1, 63}, /*x=2*/ {6, 58}, /*x=3*/ {25, 39}, /*x=4*/ {8, 56}, /*x=0*/ {18, 46},
    /*x=2*/ {62, 2}, /*x=3*/ {55, 9}, /*x=4*/ {39, 25}, /*x=0*/ {41, 23}, /*x=1*/ {2, 62},
    /*x=3*/ {28, 36}, /*x=4*/ {20, 44}, /*x=0*/ {3, 61}, /*x=1*/ {45, 19}, /*x=2*/ {61, 3},
    /*x=4*/ {27, 37}, /*x=0*/ {36, 28}, /*x=1*/ {10, 54}, /*x=2*/ {15, 49}, /*x=3*/ {56, 8}};

__constant__ int a[25] = {
    0, 6, 12, 18, 24,
    1, 7, 13, 19, 20,
    2, 8, 14, 15, 21,
    3, 9, 10, 16, 22,
    4, 5, 11, 17, 23};

__constant__ int b[25] = {
    0, 1, 2, 3, 4,
    1, 2, 3, 4, 0,
    2, 3, 4, 0, 1,
    3, 4, 0, 1, 2,
    4, 0, 1, 2, 3};

__constant__ int c[25][3] = {
    {0, 1, 2}, {1, 2, 3}, {2, 3, 4}, {3, 4, 0}, {4, 0, 1}, {5, 6, 7}, {6, 7, 8}, {7, 8, 9}, {8, 9, 5}, {9, 5, 6}, {10, 11, 12}, {11, 12, 13}, {12, 13, 14}, {13, 14, 10}, {14, 10, 11}, {15, 16, 17}, {16, 17, 18}, {17, 18, 19}, {18, 19, 15}, {19, 15, 16}, {20, 21, 22}, {21, 22, 23}, {22, 23, 24}, {23, 24, 20}, {24, 20, 21}};

__constant__ int d[25] = {
    0, 1, 2, 3, 4,
    10, 11, 12, 13, 14,
    20, 21, 22, 23, 24,
    5, 6, 7, 8, 9,
    15, 16, 17, 18, 19};

__device__  static void cuda_keccak_permutations(uint64_t *A, uint64_t *C, uint64_t *D, const int threadIndexInWrap,  int* b, int (*c)[3])
{
    int const t = threadIndexInWrap; /* greater than 1024 bit is needed, call   */
    int const s = t % 5;             /*                   kernel multiple times.*/

    for (int i = 0; i < 24; ++i)
    {
        C[t] = A[s] ^ A[s + 5] ^ A[s + 10] ^ A[s + 15] ^ A[s + 20];
        D[t] = C[b[20 + s]] ^ R64(C[b[5 + s]], 1, 63);
        C[t] = R64(A[a[t]] ^ D[b[t]], ro[t][0], ro[t][1]);
        A[d[t]] = C[c[t][0]] ^ ((~C[c[t][1]]) & C[c[t][2]]);
        A[t] ^= rc[(t == 0) ? 0 : 1][i];
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

extern "C" __global__ __launch_bounds__(1024) void kernel_lilypad_pow(
    const uint8_t *__restrict__ challenge,
    const uint64_t *__restrict__ startNonce,
    const uint64_t *__restrict__ target,
    const uint32_t n_batch,
    const uint32_t hashPerThread, uint8_t *resNonce)
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

    __shared__  int sb[25] ;
    __shared__  int sc[25][3] ;

    sb[threadIndexInWrap] = b[threadIndexInWrap];
    sc[threadIndexInWrap][0] = c[threadIndexInWrap][0];
    sc[threadIndexInWrap][1] = c[threadIndexInWrap][1];
    sc[threadIndexInWrap][2] = c[threadIndexInWrap][2];

    __shared__ uint64_t stateInBlock[WRAP_IN_BLOCK][KECCAK_STATE_SIZE];
    __shared__ uint64_t cInBlock[WRAP_IN_BLOCK][25];
    __shared__ uint64_t dInBlock[WRAP_IN_BLOCK][25];

    uint64_t *state = stateInBlock[wrapIndexInBlock];
    uint64_t *C = cInBlock[wrapIndexInBlock];
    uint64_t *D = dInBlock[wrapIndexInBlock];

    C[threadIndexInWrap] = 0;
    D[threadIndexInWrap] = 0;

    __syncwarp();
    int nonceOffset = wrapInOneLaunch * hashPerThread;
    int endNonceOffset = (wrapInOneLaunch + 1) * hashPerThread;
    for (; nonceOffset < endNonceOffset; nonceOffset++)
    {

        uint8_t *nonce;

        state[threadIndexInWrap] = 0;
        if (threadIndexInWrap == 0)
        {
            // increase nonce
            nonce = (uint8_t *)addUint256(startNonce, nonceOffset);
            memcpy(state, challenge, 32);    // Copy challenge into state
            memcpy(state + 4, nonce, 32);    // Copy nonce into state starting from index 4;

            state[8] ^= 1;
            state[16] ^= 9223372036854775808ULL;
        }

        cuda_keccak_permutations(state, C, D, threadIndexInWrap, sb,sc);

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
                memcpy(resNonce, nonce, 32);
            }

            delete nonce; // 45
        }
    }
}

//1024 32
//512  16
#define WRAP_IN_BLOCK 32  // equal to block_size/32

extern "C" __global__ __launch_bounds__(1536) void kernel_lilypad_pow_debug(
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
    __shared__ uint64_t dInBlock[WRAP_IN_BLOCK][25];

    __shared__  int sb[25] ;
    __shared__  int sc[25][3] ;

    sb[threadIndexInWrap] = b[threadIndexInWrap];
    sc[threadIndexInWrap][0] = c[threadIndexInWrap][0];
    sc[threadIndexInWrap][1] = c[threadIndexInWrap][1];
    sc[threadIndexInWrap][2] = c[threadIndexInWrap][2];

    uint64_t *state = stateInBlock[wrapIndexInBlock];
    uint64_t *C = cInBlock[wrapIndexInBlock];
    uint64_t *D = dInBlock[wrapIndexInBlock];

    C[threadIndexInWrap] = 0;
    D[threadIndexInWrap] = 0;
    // printf("C[0] %d\n",  C[1]);

    __syncwarp();
    int nonceOffset = wrapInOneLaunch * hashPerThread;
    int endNonceOffset = (wrapInOneLaunch + 1) * hashPerThread;
    for (; nonceOffset < endNonceOffset; nonceOffset++)
    {
     //   uint8_t cuda_pack[64];
        uint8_t *nonce;

        state[threadIndexInWrap] = 0;
        if (threadIndexInWrap == 0)
        {
            // increase nonce
            nonce = (uint8_t *)addUint256(startNonce, nonceOffset);
            memcpy(state, challenge, 32);    // Copy challenge into state
            memcpy(state + 4, nonce, 32);    // Copy nonce into state starting from index 4

         //   memcpy(cuda_pack, state, 64);

            state[8] ^= 1;
            state[16] ^= 9223372036854775808ULL;
        }

        cuda_keccak_permutations(state, C, D, threadIndexInWrap, sb,sc);

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
              //  reverseArray(out, 32);
              //  memcpy(hash, out, 32);
              //  memcpy(pack, cuda_pack, 64);
                memcpy(resNonce, nonce, 32);
            }

            delete nonce; // 45
        }
    }
}
