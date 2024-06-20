package main

import "C"

import (
	"context"
	"fmt"
)

var debug = true

func main() {

	fmt.Println(runPow(context.Background()))
}
