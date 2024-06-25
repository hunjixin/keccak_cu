package main

import "C"

import (
	"context"
	"fmt"
	"github/hunjixin/keccak_cu/gpulib"
)

func main() {
	gpulib.Debug = true
	fmt.Println(gpulib.RunPow(context.Background()))
}
