package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"unsafe"

	"github.com/ethereum/go-ethereum/common/math"
	"gorgonia.org/cu"
)

// void kernel_lilypad_pow(BYTE* chanllenge, uint32_t* startNonce,  uint32_t* target,  BYTE* resNonce, WORD n_batch)
func kernel_lilypad_pow(fn cu.Function, challenge [32]byte, startNonce *big.Int, difficulty *big.Int, batch uint64) (*big.Int, error) {
	dIn1, err := cu.MemAlloc(32)
	if err != nil {
		return nil, err
	}

	dIn2, err := cu.MemAlloc(32)
	if err != nil {
		return nil, err
	}

	dIn3, err := cu.MemAlloc(32)
	if err != nil {
		return nil, err
	}

	dHash, err := cu.MemAlloc(32)
	if err != nil {
		return nil, err
	}

	dPack, err := cu.MemAlloc(64)
	if err != nil {
		return nil, err
	}

	dOut, err := cu.MemAlloc(32)
	if err != nil {
		return nil, err
	}

	thread := 256
	block := (int(batch) + thread - 1) / thread

	//(BYTE* indata,	 WORD inlen,	 BYTE* outdata,	 WORD n_batch,	 WORD KECCAK_BLOCK_SIZE)
	args := []unsafe.Pointer{
		unsafe.Pointer(&dIn1),
		unsafe.Pointer(&dIn2),
		unsafe.Pointer(&dIn3),
		unsafe.Pointer(&batch),
		unsafe.Pointer(&dOut),
		unsafe.Pointer(&dHash),
		unsafe.Pointer(&dPack),
	}

	if err = cu.MemcpyHtoD(dIn1, unsafe.Pointer(&challenge[0]), 32); err != nil {
		return nil, err
	}

	startNonceBytes := math.U256Bytes(startNonce)
	slices.Reverse(startNonceBytes)
	if err = cu.MemcpyHtoD(dIn2, unsafe.Pointer(&startNonceBytes[0]), 32); err != nil {
		return nil, err
	}

	difficutyBytes := math.U256Bytes(difficulty)
	slices.Reverse(difficutyBytes) //to big
	if err = cu.MemcpyHtoD(dIn3, unsafe.Pointer(&difficutyBytes[0]), 32); err != nil {
		return nil, err
	}

	//thread := 256
	//block := (int(inNum) + thread - 1) / thread
	if err = fn.LaunchAndSync(thread, 1, 1, block, 1, 1, 1, cu.Stream{}, args); err != nil {
		return nil, err
	}

	hOut := make([]byte, 32)
	if err = cu.MemcpyDtoH(unsafe.Pointer(&hOut[0]), dOut, 32); err != nil {
		return nil, err
	}

	hHash := make([]byte, 32)
	if err = cu.MemcpyDtoH(unsafe.Pointer(&hHash[0]), dHash, 32); err != nil {
		return nil, err
	}
	fmt.Println("cuda hash result:", hex.EncodeToString(hHash))

	hPack := make([]byte, 64)
	if err = cu.MemcpyDtoH(unsafe.Pointer(&hPack[0]), dPack, 64); err != nil {
		return nil, err
	}
	fmt.Println("cuda pack result: ", hex.EncodeToString(hPack))

	cu.MemFree(dIn1)
	cu.MemFree(dIn2)
	cu.MemFree(dOut)
	return new(big.Int).SetBytes(hOut), nil
}
