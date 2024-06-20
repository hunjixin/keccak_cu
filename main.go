package main

import "C"

import (
	"context"
	"fmt"
)

var debug = false

func main() {

	fmt.Println(runPow(context.Background()))
}
