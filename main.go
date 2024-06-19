package main

import "C"

import (
	"context"
	"fmt"
)

func main() {

	fmt.Println(runPow(context.Background()))
}
