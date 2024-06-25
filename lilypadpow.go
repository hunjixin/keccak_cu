package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"unsafe"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/pkg/errors"
	"gorgonia.org/cu"
)

func kernel_lilypad_pow_with_ctx(cuCtx *cu.Ctx, fn cu.Function, challenge [32]byte, startNonce *big.Int, difficulty *big.Int, thread, block int, hashPerThread int) (*big.Int, error) {
	dIn1, err := cuCtx.MemAllocManaged(32, cu.AttachGlobal)
	if err != nil {
		return nil, err
	}

	dIn2, err := cuCtx.MemAllocManaged(32, cu.AttachGlobal)
	if err != nil {
		return nil, err
	}

	dIn3, err := cuCtx.MemAllocManaged(32, cu.AttachGlobal)
	if err != nil {
		return nil, err
	}

	dOut, err := cuCtx.MemAllocManaged(32, cu.AttachGlobal)
	if err != nil {
		return nil, err
	}

	batch := int64(thread * block)
	//(BYTE* indata,	 WORD inlen,	 BYTE* outdata,	 WORD n_batch,	 WORD KECCAK_BLOCK_SIZE)
	args := []unsafe.Pointer{
		unsafe.Pointer(&dIn1),
		unsafe.Pointer(&dIn2),
		unsafe.Pointer(&dIn3),
		unsafe.Pointer(&batch),
		unsafe.Pointer(&hashPerThread),
		unsafe.Pointer(&dOut),
	}

	cuCtx.MemcpyHtoD(dIn1, unsafe.Pointer(&challenge[0]), 32)

	startNonceBytes := math.U256Bytes(startNonce)
	cuCtx.MemcpyHtoD(dIn2, unsafe.Pointer(&startNonceBytes[0]), 32)

	difficutyBytes := math.U256Bytes(difficulty)
	slices.Reverse(difficutyBytes) //to big
	cuCtx.MemcpyHtoD(dIn3, unsafe.Pointer(&difficutyBytes[0]), 32)

	cuCtx.LaunchKernel(fn, thread, 1, 1, block, 1, 1, 1, cu.Stream{}, args)
	cuCtx.Synchronize()

	hOut := make([]byte, 32)
	cuCtx.MemcpyDtoH(unsafe.Pointer(&hOut[0]), dOut, 32)

	cuCtx.MemFree(dIn1)
	cuCtx.MemFree(dIn2)
	cuCtx.MemFree(dIn3)
	cuCtx.MemFree(dOut)

	return new(big.Int).SetBytes(hOut), nil
}

func kernel_lilypad_pow_with_ctx_debug(cuCtx *cu.Ctx, fn cu.Function, challenge [32]byte, startNonce *big.Int, difficulty *big.Int, thread, block int, hashPerThread int) (*big.Int, error) {
	dIn1, err := cuCtx.MemAllocManaged(32, cu.AttachGlobal)
	if err != nil {
		return nil, err
	}

	dIn2, err := cuCtx.MemAllocManaged(32, cu.AttachGlobal)
	if err != nil {
		return nil, err
	}

	dIn3, err := cuCtx.MemAllocManaged(32, cu.AttachGlobal)
	if err != nil {
		return nil, err
	}

	dHash, err := cuCtx.MemAllocManaged(32, cu.AttachGlobal)
	if err != nil {
		return nil, err
	}

	dPack, err := cuCtx.MemAllocManaged(64, cu.AttachGlobal)
	if err != nil {
		return nil, err
	}

	dOut, err := cuCtx.MemAllocManaged(32, cu.AttachGlobal)
	if err != nil {
		return nil, err
	}

	batch := int64(thread * block)
	//(BYTE* indata,	 WORD inlen,	 BYTE* outdata,	 WORD n_batch,	 WORD KECCAK_BLOCK_SIZE)
	args := []unsafe.Pointer{
		unsafe.Pointer(&dIn1),
		unsafe.Pointer(&dIn2),
		unsafe.Pointer(&dIn3),
		unsafe.Pointer(&batch),
		unsafe.Pointer(&hashPerThread),
		unsafe.Pointer(&dOut),
		unsafe.Pointer(&dHash),
		unsafe.Pointer(&dPack),
	}

	cuCtx.MemcpyHtoD(dIn1, unsafe.Pointer(&challenge[0]), 32)

	startNonceBytes := math.U256Bytes(startNonce)
	cuCtx.MemcpyHtoD(dIn2, unsafe.Pointer(&startNonceBytes[0]), 32)

	difficutyBytes := math.U256Bytes(difficulty)
	slices.Reverse(difficutyBytes) //to big
	cuCtx.MemcpyHtoD(dIn3, unsafe.Pointer(&difficutyBytes[0]), 32)

	cuCtx.LaunchKernel(fn, thread, 1, 1, block, 1, 1, 1, cu.Stream{}, args)
	if err = cuCtx.Error(); err != nil {
		return nil, fmt.Errorf("launch kernel fail maybe decrease threads help %w", err)
	}
	cuCtx.Synchronize()

	hOut := make([]byte, 32)
	cuCtx.MemcpyDtoH(unsafe.Pointer(&hOut[0]), dOut, 32)

	hHash := make([]byte, 32)
	cuCtx.MemcpyDtoH(unsafe.Pointer(&hHash[0]), dHash, 32)
	if debug {
		fmt.Println("cuda hash result:", hex.EncodeToString(hHash))
	}

	hPack := make([]byte, 64)
	cuCtx.MemcpyDtoH(unsafe.Pointer(&hPack[0]), dPack, 64)

	if debug {
		fmt.Println("cuda pack result: ", hex.EncodeToString(hPack))
	}
	cuCtx.MemFree(dIn1)
	cuCtx.MemFree(dIn2)
	cuCtx.MemFree(dIn3)
	cuCtx.MemFree(dHash)
	cuCtx.MemFree(dPack)
	cuCtx.MemFree(dOut)

	return new(big.Int).SetBytes(hOut), nil
}

func setupGPU() (*cu.Ctx, error) {
	devices, _ := cu.NumDevices()

	if devices == 0 {
		return nil, errors.Errorf("NoDevice")
	}

	dev := cu.Device(0)

	return cu.NewContext(dev, cu.SchedAuto), nil
}
