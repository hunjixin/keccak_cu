package main

import (
	"C"
	"context"
	"crypto/rand"
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

	_, err = findDevice()
	if err != nil {
		return err
	}

	module, err := cu.LoadData(string(file))
	if err != nil {
		return err
	}

	fn, err := module.Function("kernel_keccak_hash")

	piece := [64]byte{}
	rand.Read(piece[:])

	hash := crypto.Keccak256Hash(piece[:])
	fmt.Println(hex.EncodeToString(hash[:]))

	result, err := cuda_batch_keccak(fn, [][64]byte{piece})
	if err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(result[0][:]))
}

func findDevice() (dev cu.Device, err error) {
	devices, _ := cu.NumDevices()

	if devices == 0 {
		err = errors.Errorf("NoDevice")
		return
	}

	dev = cu.Device(0)
	return
}

func cuda_batch_keccak(fn cu.Function, in [][64]byte) ([][32]byte, error) {
	inNum := int64(len(in))

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

	if err = cu.MemcpyHtoD(dIn, unsafe.Pointer(&in[0]), 64*inNum); err != nil {
		return nil, err
	}

	thread := 256
	block := (int(inNum) + thread - 1) / thread
	if err = fn.LaunchAndSync(thread, 1, 1, block, 1, 1, 1, cu.Stream{}, args); err != nil {
		return nil, err
	}

	out := make([][32]byte, inNum)
	if err = cu.MemcpyDtoH(unsafe.Pointer(&out[0]), dOut, 32*inNum); err != nil {
		return nil, err
	}

	return out, nil
}
