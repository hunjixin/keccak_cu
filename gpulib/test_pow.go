package gpulib

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
	"gorgonia.org/cu"
)

func RunPow(ctx context.Context) error {
	dev2, _ := cu.GetDevice(0)
	fmt.Println(dev2.Attributes(cu.MaxBlockDimX, cu.MaxBlockDimX))

	cuCtx, err := SetupGPU()
	if err != nil {
		fmt.Println("xxx")
		return err
	}
	defer cuCtx.Close()

	module, err := cuCtx.Load("keccak.ptx")
	if err != nil {
		return err
	}

	fn, err := module.Function("kernel_lilypad_pow_debug")
	if err != nil {
		fmt.Println("not found")
		return err
	}

	challenge := [32]byte{}
	rand.Read(challenge[:])
	//										 115792089237316195423570985008687907853269984665640564039457584007913129639935
	difficulty, _ := new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007913129639935", 10)
	//2221842798488549893930113429797694032668256326301844165995655665287168
	startNonce, _ := new(big.Int).SetString("38494386881236579867968611199111111111865446613467851139674583965", 10)
	count := 0
	nowT := time.Now()

	thread := 1
	block := 32
	batch := thread * block
	threadPerThread := 1
	for {
		resultNonce, err := Kernel_lilypad_pow_with_ctx_debug(cuCtx, fn, challenge, startNonce, difficulty, thread, block, threadPerThread) // kernel_lilypad_pow_with_ctx_debug(cuCtx, fn, challenge, startNonce, difficulty, 32, 1024)
		if err != nil {
			return err
		}
		err = cuCtx.Error()
		if err != nil {
			fmt.Println(err)
			return nil
		}

		count += batch * threadPerThread
		if count%(1000*1000) == 0 {
			secs := time.Since(nowT).Seconds()
			if secs > 0 {
				fmt.Println("speed m", float64(count/1000/1000)/secs)
			}
		}
		startNonce = new(big.Int).Add(startNonce, big.NewInt(int64(batch)))
		if resultNonce.BitLen() == 0 {
			fmt.Println("not found ", startNonce.String())
			continue
			//return nil
		}

		//verify
		hashNumber, err := CalculateHashNumber(challenge, resultNonce)
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

	return nil
}

func CalculateHashNumber(challenge [32]byte, nonce *big.Int) (*uint256.Int, error) {
	data, err := FormatMinerArgs(challenge, nonce)
	if err != nil {
		return nil, err
	}

	if Debug {
		fmt.Println("cpu pack result:", hex.EncodeToString(data))
	}

	// Calculate Keccak-256 hash
	hashResult := crypto.Keccak256(data)

	if Debug {

		fmt.Println("cpu hash result:", hex.EncodeToString(hashResult))
	}

	fmt.Println("hashnumber ", new(uint256.Int).SetBytes(hashResult).String())
	return new(uint256.Int).SetBytes(hashResult), nil
}
