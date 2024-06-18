package main

import "C"

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"unsafe"

	"github.com/pkg/errors"
	"gorgonia.org/cu"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	fmt.Println(run(context.Background()))
}

func run(ctx context.Context) error {
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

	fn, err := module.Function("kernel_keccak_hash")
	if err != nil {
		fmt.Println(":xxxxx")
		return err
	}

	batch := 1000

	input := make([][64]byte, batch)
	for i := 0; i < batch; i++ {
		piece := [64]byte{}
		rand.Read(piece[:])
		input = append(input, piece)
	}

	results, err := cuda_batch_keccak(fn, input)
	if err != nil {
		return err
	}
	for index, result := range results {
		hash := crypto.Keccak256Hash(input[index][:])
		if !bytes.Equal(hash[:], result[:]) {
			panic("xxxxxxxxxxxx")
		}
		fmt.Println("-----------")
		fmt.Println("input: ", hex.EncodeToString(input[index][:]))
		fmt.Println("cpu result: ", hex.EncodeToString(hash[:]))
		fmt.Println("cuda result: ", hex.EncodeToString(result[:]))
	}

	return nil
}

func testSetup() (dev cu.Device, ctx cu.CUContext, err error) {
	devices, _ := cu.NumDevices()

	if devices == 0 {
		err = errors.Errorf("NoDevice")
		return
	}

	dev = cu.Device(0)
	if ctx, err = dev.MakeContext(cu.SchedAuto); err != nil {
		return
	}
	return
}

func cuda_batch_keccak(fn cu.Function, hIn [][64]byte) ([][32]byte, error) {
	inNum := int64(len(hIn))

	dIn, err := cu.MemAlloc(64 * inNum)
	if err != nil {
		return nil, err
	}

	dOut, err := cu.MemAlloc(32 * inNum)
	if err != nil {
		return nil, err
	}

	inLen := int64(64)
	block_size := int64(256 >> 3)
	//(BYTE* indata,	 WORD inlen,	 BYTE* outdata,	 WORD n_batch,	 WORD KECCAK_BLOCK_SIZE)
	args := []unsafe.Pointer{
		unsafe.Pointer(&dIn),
		unsafe.Pointer(&inLen),
		unsafe.Pointer(&dOut),

		unsafe.Pointer(&inNum),
		unsafe.Pointer(&block_size),
	}

	if err = cu.MemcpyHtoD(dIn, unsafe.Pointer(&hIn[0]), 64*inNum); err != nil {
		return nil, err
	}

	thread := 256
	block := (int(inNum) + thread - 1) / thread
	if err = fn.LaunchAndSync(thread, 1, 1, block, 1, 1, 1, cu.Stream{}, args); err != nil {
		return nil, err
	}

	hOut := make([][32]byte, inNum)
	if err = cu.MemcpyDtoH(unsafe.Pointer(&hOut[0]), dOut, 32*inNum); err != nil {
		return nil, err
	}

	cu.MemFree(dIn)
	cu.MemFree(dOut)
	return hOut, nil
}
