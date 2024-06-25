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

__constant__ static const int r[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};

__constant__ static const int piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

__device__ __forceinline__ static void cuda_keccak_permutations(uint64_t *state)
{
    int i, j;
    uint64_t temp, C[5];

    for (int round = 0; round < 24; round++)
    {
        // Theta
        for (i = 0; i < 5; i++)
        {
            C[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        }

        for (i = 0; i < 5; i++)
        {
            temp = C[(i + 4) % 5] ^ asm_cuda_keccak_ROTL64(C[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5)
            {
                state[j + i] ^= temp;
            }
        }

        // Rho Pi
        temp = state[1];
        for (i = 0; i < 24; i++)
        {
            j = piln[i];
            C[0] = state[j];
            state[j] = asm_cuda_keccak_ROTL64(temp, r[i]);
            temp = C[0];
        }

        //  Chi
        for (j = 0; j < 25; j += 5)
        {
            for (i = 0; i < 5; i++)
            {
                C[i] = state[j + i];
            }
            for (i = 0; i < 5; i++)
            {
                state[j + i] ^= (~C[(i + 1) % 5]) & C[(i + 2) % 5];
            }
        }

        //  Iota
        state[0] ^= CUDA_KECCAK_CONSTS[round];
    }
}

__noinline__ __device__ static bool hashbelowtarget(const uint64_t *const __restrict__ hash, const uint64_t *const __restrict__ target)
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

extern "C" __global__ __launch_bounds__(1024, 1) void kernel_lilypad_pow(
    const uint8_t *__restrict__ challenge,
    const uint64_t *__restrict__ startNonce,
    const uint64_t *__restrict__ target,
    const uint32_t n_batch,
    const uint32_t hashPerThread,
    uint8_t *resNonce)
{
    uint32_t thread = blockIdx.x * blockDim.x + threadIdx.x;
    if (thread >= n_batch)
    {
        return;
    }

    for (uint32_t i = thread * hashPerThread; i < (thread + 1) * hashPerThread; i++)
    {
        // increase nonce
        uint8_t *nonce = (uint8_t *)addUint256(startNonce, i);
        uint64_t state[KECCAK_STATE_SIZE];
        memset(state, 0, sizeof(state));

        memcpy(state, challenge, 32); // Copy challenge into state
        memcpy(state + 4, nonce, 32); // Copy nonce into state starting from index 4

        // uint8_t cuda_pack[64];
        // memcpy(cuda_pack, state, 64);

        state[8] ^= 1;
        state[16] ^= 9223372036854775808ULL;

        cuda_keccak_permutations(state);

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

extern "C" __global__ __launch_bounds__(1024, 1) void kernel_lilypad_pow_debug(
    const uint8_t *__restrict__ challenge,
    const uint64_t *__restrict__ startNonce,
    const uint64_t *__restrict__ target,
    const uint32_t n_batch,
    const uint32_t hashPerThread, uint8_t *resNonce, uint8_t *hash, uint8_t *pack)
{
    uint32_t thread = blockIdx.x * blockDim.x + threadIdx.x;
    if (thread >= n_batch)
    {
        return;
    }

    if (thread >= 25)
    {
        return;
    }

    for (int i = thread * hashPerThread; i < (thread + 1) * hashPerThread; i++)
    {
        uint8_t cuda_pack[64];
        uint8_t *nonce;
        uint64_t state[KECCAK_STATE_SIZE];
        if (thread == 0)
        {
            // increase nonce
            nonce = (uint8_t *)addUint256(startNonce, i);

            memset(state, 0, sizeof(state));

            memcpy(state, challenge, 32); // Copy challenge into state
            memcpy(state + 4, nonce, 32); // Copy nonce into state starting from index 4

            memcpy(cuda_pack, state, 64);

            state[8] ^= 1;
            state[16] ^= 9223372036854775808ULL;
        }

        cuda_keccak_permutations(state);

        if (thread == 0)
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
