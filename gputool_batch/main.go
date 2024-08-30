package main

import (
	"context"
	"crypto/rand"
	"encoding/csv"
	"flag"
	"fmt"
	"github/hunjixin/keccak_cu/gpulib"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/ALTree/bigfloat"
	"gorgonia.org/cu"
)

var grid int
var block int
var threadPerThread int
var difficultyStr string
var repeat int

var (
	uint256Max, _ = new(big.Float).SetString("115792089237316195423570985008687907853269984665640564039457584007913129639935")
)

func esitimateHashRate(difficulty *big.Float, durS float64, probability float64) *big.Float {
	ne := new(big.Float).Sub(uint256Max, difficulty)
	not_probability := new(big.Float).Quo(ne, uint256Max)

	targetProb := new(big.Float).SetFloat64(probability)

	tmp := new(big.Float).Mul(big.NewFloat(durS), bigfloat.Log(not_probability))
	hashRate := new(big.Float).Quo(bigfloat.Log(targetProb), tmp)
	hashRate = hashRate.Quo(hashRate, big.NewFloat(1000*1000))
	return hashRate
}

func main() {
	gpulib.Debug = false
	flag.IntVar(&repeat, "repeat", 100, "repeat time")
	flag.IntVar(&grid, "grid", 38, "grid size")
	flag.IntVar(&block, "block", 1024, "block size")
	flag.IntVar(&threadPerThread, "hash_per_thread", 1, "hash to calculate per threads")
	flag.StringVar(&difficultyStr, "difficulty", "222184279848854989393011342979769403266326301844165995655665287168", "difficulty")
	flag.Parse()
	fmt.Println(runPow(context.Background()))
}

type Record struct {
	EstimateHashRate string
	TimeDuration     string
}

func runPow(ctx context.Context) error {
	dev2, _ := cu.GetDevice(0)
	values, err := dev2.Attributes(cu.MaxRegistersPerBlock, cu.RegistersPerBlock, cu.MaxBlockDimX, cu.MaxBlockDimX, cu.MultiprocessorCount, cu.MaxSharedMemoryPerBlock)
	if err != nil {
		return err
	}
	fmt.Println("MaxRegistersPerBlock", values[0])
	fmt.Println("RegistersPerBlock", values[1])
	fmt.Println("MaxBlockDimX", values[2])
	fmt.Println("MaxBlockDimX", values[3])
	fmt.Println("MultiprocessorCount", values[4])
	fmt.Println("MaxSharedMemoryPerBlock", values[5])

	cuCtx, err := gpulib.SetupGPU()
	if err != nil {
		return err
	}
	defer cuCtx.Close()

	fs, err := os.CreateTemp(os.TempDir(), "*")
	if err != nil {
		return err
	}

	_, err = fs.WriteString(gpulib.PTX)
	if err != nil {
		return err
	}

	err = fs.Close()
	if err != nil {
		return err
	}

	module, err := cuCtx.Load(fs.Name())
	if err != nil {
		return err
	}

	fn, err := module.Function("kernel_lilypad_pow")
	if err != nil {
		fmt.Println("not found")
		return err
	}

	//										 115792089237316195423570985008687907853269984665640564039457584007913129639935
	difficulty, _ := new(big.Int).SetString(difficultyStr, 10)
	//2221842798488549893930113429797694032668256326301844165995655665287168

	batch := grid * block * threadPerThread
	fmt.Println("use arg", grid, block, threadPerThread)
	fmt.Println(batch, " hash per kernel")

	csvFs, err := os.Create("record.csv")
	if err != nil {
		return err
	}

	w := csv.NewWriter(csvFs)
	w.Write([]string{"realHashrate", "hashrate", "timedur"})
	for i := 0; i < repeat; i++ {
		challenge := [32]byte{}
		rand.Read(challenge[:])

		nonce := [32]byte{}
		rand.Read(nonce[:])
		startNonce := new(big.Int).SetBytes(nonce[:])

		count := 0
		nowT := time.Now()
		curNonce := new(big.Int).SetBytes(startNonce.Bytes())
		realHashrate := 0.0
		for {
			resultNonce, err := gpulib.Kernel_lilypad_pow_with_ctx(cuCtx, fn, challenge, curNonce, difficulty, grid, block, threadPerThread) // kernel_lilypad_pow_with_ctx_debug(cuCtx, fn, challenge, startNonce, difficulty, 32, 1024)
			if err != nil {
				return err
			}
			err = cuCtx.Error()
			if err != nil {
				fmt.Println(err)
				return err
			}

			count += batch
			if count%(batch*4) == 0 {
				secs := float64(time.Since(nowT).Milliseconds()) / 1000
				if secs > 0 {
					realHashrate = float64(count/1000/1000) / secs
					fmt.Printf("%2f speed MHASH/s  cur nonce: %s \n", realHashrate, curNonce.String())
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
				dur := float64(time.Since(nowT).Milliseconds()) / 1000.0
				fmt.Println("********* find nonce ******")
				fmt.Println("time used ", time.Since(nowT).Milliseconds(), "ms")
				fmt.Println("gap ", new(big.Int).Sub(resultNonce, startNonce).String())
				fmt.Println("hashResult ", hashNumber.String())
				fmt.Println("nonce result", resultNonce.String())
				fmt.Println("difficulty ", difficulty.String())
				difficultyF, _ := new(big.Float).SetString(difficulty.String())
				hashRate := esitimateHashRate(difficultyF, dur, 0.00001)
				fmt.Println("real hashreate ", strconv.FormatFloat(realHashrate, 'f', 2, 64))
				fmt.Println("estimate hashreate ", hashRate.Text('f', 2))
				w.Write([]string{
					strconv.FormatFloat(realHashrate, 'f', 2, 64),
					hashRate.Text('f', 2),
					strconv.FormatFloat(dur, 'f', 2, 64),
				})
				w.Flush()
				break
			} else {
				panic("should never happen")
			}

		}

	}

	return nil
}
