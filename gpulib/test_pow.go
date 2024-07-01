package gpulib

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
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

	fs, err := os.CreateTemp(os.TempDir(), "*")
	if err != nil {
		return err
	}

	_, err = fs.WriteString(PTX)
	if err != nil {
		return err
	}

	err = fs.Close()
	if err != nil {
		return err
	}

	module, err := cuCtx.Load(fs.Name())
	if err != nil {
		return fmt.Errorf("load module %w", err)
	}

	fn, err := module.Function("kernel_lilypad_pow_debug")
	if err != nil {
		fmt.Println("not found")
		return err
	}

	challenge := [32]byte{}
	//rand.Read(challenge[:])
	challenge2, _ := hex.DecodeString("c860cc1da771e99a355ccf0bc7c56dfecab02cc5ae04b81b515140adae7cc079")
	copy(challenge[:], challenge2)

	//										 115792089237316195423570985008687907853269984665640564039457584007913129639935
	difficulty, _ := new(big.Int).SetString("22218427984885498939301134297976940326682563263018441659956556652871", 10)
	//1157920892373161954235709850086879078532699846656405640394575840079131296399
	//641327565936886061866070137176519482567993606854698372487583526443271781096
	//2221842798488549893930113429797694032668256326301844165995655665287168
	startNonce, _ := new(big.Int).SetString("38494386881236579867968611199111111111865446613467851139674583965", 10)
	count := 0
	nowT := time.Now()

	fmt.Println(hex.EncodeToString(difficulty.Bytes()))
	thread := 68
	block := 1024
	batch := thread * block
	threadPerThread := 500
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
			//fmt.Println("not found ", startNonce.String())
			//return nil
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
