package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
	"gorgonia.org/cu"
)

func runPow(ctx context.Context) error {
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

	fn, err := module.Function("kernel_lilypad_pow")
	if err != nil {
		fmt.Println(":xxxxx")
		return err
	}

	challenge := [32]byte{}
	rand.Read(challenge[:])
	nonce, _ := new(big.Int).SetString("384945743861236579867968647573457271936748661346785439674583967542", 10)
	difficulty, _ := new(big.Int).SetString("57896044618658097711785492504343953926634992332820282019728792003956564819967", 10)
	resultNonce, err := kernel_lilypad_pow(fn, challenge, nonce, difficulty, 1)
	if err != nil {
		return err
	}

	if resultNonce.BitLen() == 0 {
		fmt.Println("not found")
		return nil
	}

	//verify
	hashNumber, err := calculateHashNumber(challenge, resultNonce)
	if err != nil {
		panic(err)
	}
	fmt.Println("difficulty ", difficulty.String())
	fmt.Println("nonce result", resultNonce.String())

	if hashNumber.ToBig().Cmp(difficulty) == -1 {
		panic("err")
	}
	time.Sleep(time.Hour)
	return nil
}

func calculateHashNumber(challenge [32]byte, nonce *big.Int) (*uint256.Int, error) {
	data, err := formatMinerArgs(challenge, nonce)
	if err != nil {
		return nil, err
	}

	fmt.Println("cpu pack result:", hex.EncodeToString(data))
	// Calculate Keccak-256 hash
	hashResult := crypto.Keccak256(data)
	fmt.Println("cpu hash result:", hex.EncodeToString(hashResult))
	fmt.Println("hashnumber ", new(uint256.Int).SetBytes(hashResult).String())
	return new(uint256.Int).SetBytes(hashResult), nil
}
