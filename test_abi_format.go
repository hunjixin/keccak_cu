package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"slices"
	"unsafe"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common/math"
	"gorgonia.org/cu"
)

func run_kernal_pack_argument_test(ctx context.Context) error {
	file, err := os.ReadFile("keccak.ptx")
	if err != nil {
		return err
	}

	_, _, err = testSetup()
	if err != nil {
		return err
	}

	module, err := cu.LoadData(string(file))
	if err != nil {
		return err
	}

	fn, err := module.Function("kernal_pack_argument_test")
	if err != nil {
		fmt.Println(":xxxxx")
		return err
	}

	challenge := [32]byte{}
	rand.Read(challenge[:])
	nonce, _ := new(big.Int).SetString("3849457438612365768476459867968647573457271936748661346785439674583967542", 10)
	result, err := cuda_formatMinerArgs(fn, challenge, nonce)
	if err != nil {
		panic(err)
	}

	fmt.Println("cuda result:", hex.EncodeToString(result[:]))

	result2, _ := formatMinerArgs(challenge, new(big.Int).Add(nonce, big.NewInt(1266523343)))
	fmt.Println("go result  :", hex.EncodeToString(result2[:]))
	return nil
}

func cuda_formatMinerArgs(fn cu.Function, hChanllenge [32]byte, nonce *big.Int) ([]byte, error) {
	dIn1, err := cu.MemAlloc(32)
	if err != nil {
		return nil, err
	}

	dIn2, err := cu.MemAlloc(32)
	if err != nil {
		return nil, err
	}

	dOut, err := cu.MemAlloc(64)
	if err != nil {
		return nil, err
	}

	//(BYTE* indata,	 WORD inlen,	 BYTE* outdata,	 WORD n_batch,	 WORD KECCAK_BLOCK_SIZE)
	args := []unsafe.Pointer{
		unsafe.Pointer(&dIn1),
		unsafe.Pointer(&dIn2),
		unsafe.Pointer(&dOut),
	}

	if err = cu.MemcpyHtoD(dIn1, unsafe.Pointer(&hChanllenge[0]), 32); err != nil {
		return nil, err
	}

	inByte := math.U256Bytes(nonce)
	slices.Reverse(inByte)
	if err = cu.MemcpyHtoD(dIn2, unsafe.Pointer(&inByte[0]), 32); err != nil {
		return nil, err
	}

	if err = fn.LaunchAndSync(1, 1, 1, 1, 1, 1, 1, cu.Stream{}, args); err != nil {
		return nil, err
	}

	hOut := make([]byte, 64)
	if err = cu.MemcpyDtoH(unsafe.Pointer(&hOut[0]), dOut, 64); err != nil {
		return nil, err
	}

	cu.MemFree(dIn1)
	cu.MemFree(dIn2)
	cu.MemFree(dOut)
	return hOut, nil
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
