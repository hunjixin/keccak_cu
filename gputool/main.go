package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"github/hunjixin/keccak_cu/gpulib"
	"math/big"
	"time"
)

var grid int
var block int
var threadPerThread int

func main() {
	flag.IntVar(&grid, "grid", 38, "grid size")
	flag.IntVar(&block, "block", 1024, "block size")
	flag.IntVar(&threadPerThread, "hash_per_thread", 100, "hash to calculate per threads")
	flag.Parse()
	fmt.Println(runPow(context.Background()))
}
func runPow(ctx context.Context) error {
	cuCtx, err := gpulib.SetupGPU()
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

	fmt.Println("use arg", grid, block, threadPerThread)

	challenge := [32]byte{}
	rand.Read(challenge[:])
	//										 115792089237316195423570985008687907853269984665640564039457584007913129639935
	difficulty, _ := new(big.Int).SetString("222184279848854989393011342979769403266326301844165995655665287168", 10)
	//2221842798488549893930113429797694032668256326301844165995655665287168
	startNonce, _ := new(big.Int).SetString("38494386881236579867968611199111111111865446613467851139674583965", 10)
	count := 0
	nowT := time.Now()

	batch := grid * block * threadPerThread

	curNonce := new(big.Int).SetBytes(startNonce.Bytes())

	for {
		resultNonce, err := gpulib.Kernel_lilypad_pow_with_ctx(cuCtx, fn, challenge, curNonce, difficulty, grid, block, threadPerThread) // kernel_lilypad_pow_with_ctx_debug(cuCtx, fn, challenge, startNonce, difficulty, 32, 1024)
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
		hashNumber, err := gpulib.CalculateHashNumber(challenge, resultNonce)
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
