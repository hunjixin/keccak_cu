package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"slices"
	"time"
	"unsafe"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"gorgonia.org/cu"
)

var grid int
var block int

func main() {
	flag.IntVar(&grid, "grid", 38, "grid size")
	flag.IntVar(&block, "block", 1024, "block size")
	flag.Parse()
	fmt.Println(runPow(context.Background()))
}
func runPow(ctx context.Context) error {
	cuCtx, err := setupGPU()
	if err != nil {
		fmt.Println("xxx")
		return err
	}
	defer cuCtx.Close()

	module, err := cuCtx.Load("keccak.ptx")
	if err != nil {
		return err
	}

	fn, err := module.Function("kernel_lilypad_pow")
	if err != nil {
		fmt.Println("not found")
		return err
	}

	challenge := [32]byte{}
	rand.Read(challenge[:])
	//										 115792089237316195423570985008687907853269984665640564039457584007913129639935
	difficulty, _ := new(big.Int).SetString("222184279848854989393011342979769403266326301844165995655665287168", 10)
	//2221842798488549893930113429797694032668256326301844165995655665287168
	startNonce, _ := new(big.Int).SetString("38494386881236579867968611199111111111865446613467851139674583965", 10)
	count := 0
	nowT := time.Now()

	batch := grid * block

	curNonce := new(big.Int).SetBytes(startNonce.Bytes())

	for {
		resultNonce, err := kernel_lilypad_pow_with_ctx(cuCtx, fn, challenge, curNonce, difficulty, grid, block) // kernel_lilypad_pow_with_ctx_debug(cuCtx, fn, challenge, startNonce, difficulty, 32, 1024)
		if err != nil {
			return err
		}
		err = cuCtx.Error()
		if err != nil {
			fmt.Println(err)
			return nil
		}

		count += batch
		if count%(batch*10) == 0 {
			secs := time.Since(nowT).Seconds()
			if secs > 0 {
				fmt.Println("speed MHASH/s", float64(count/1000/1000)/secs)
			}
		}
		curNonce = new(big.Int).Add(curNonce, big.NewInt(int64(batch)))
		if resultNonce.BitLen() == 0 {
			continue
		}

		//verify
		hashNumber, err := calculateHashNumber(challenge, resultNonce)
		if err != nil {
			panic(err)
		}

		if hashNumber.ToBig().Cmp(difficulty) == -1 {
			fmt.Println("********* find nonce ******")
			fmt.Println("gap ", new(big.Int).Sub(resultNonce, startNonce).String())
			fmt.Println("difficulty ", difficulty.String())
			fmt.Println("hashResult ", hashNumber.String())
			fmt.Println("nonce result", resultNonce.String())
			return nil
		} else {
			panic("should never happen")
		}

	}
}

func kernel_lilypad_pow_with_ctx(cuCtx *cu.Ctx, fn cu.Function, challenge [32]byte, startNonce *big.Int, difficulty *big.Int, thread, block int) (*big.Int, error) {
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

func setupGPU() (*cu.Ctx, error) {
	devices, _ := cu.NumDevices()

	if devices == 0 {
		return nil, errors.Errorf("NoDevice")
	}

	dev := cu.Device(0)

	return cu.NewContext(dev, cu.SchedAuto), nil
}

func calculateHashNumber(challenge [32]byte, nonce *big.Int) (*uint256.Int, error) {
	data, err := formatMinerArgs(challenge, nonce)
	if err != nil {
		return nil, err
	}

	// Calculate Keccak-256 hash
	hashResult := crypto.Keccak256(data)

	fmt.Println("hashnumber ", new(uint256.Int).SetBytes(hashResult).String())
	return new(uint256.Int).SetBytes(hashResult), nil
}

func formatMinerArgs(challenge [32]byte, nonce *big.Int) ([]byte, error) {
	//todo use nonce in replace instead of building from scratch for better performance
	// keccak256(abi.encodePacked(lastChallenge, msg.sender, nodeId));
	bytes32Ty, _ := abi.NewType("bytes32", "", nil)
	uint256Ty, _ := abi.NewType("uint256", "", nil)

	arguments := abi.Arguments{
		{
			Type: bytes32Ty,
		},
		{
			Type: uint256Ty,
		},
	}

	bytes, err := arguments.Pack(
		challenge,
		nonce,
	)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}
