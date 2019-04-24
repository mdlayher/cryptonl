// Command cryptonl uses package cryptonl to produce a list of algorithms
// registered with the Linux kernel crypto API.
package main

import (
	"fmt"
	"log"

	"github.com/mdlayher/cryptonl"
)

func main() {
	c, err := cryptonl.Dial()
	if err != nil {
		log.Fatalf("failed to dial: %v", err)
	}
	defer c.Close()

	algs, err := c.Algorithms()
	if err != nil {
		log.Fatalf("failed to get algorithms: %v", err)
	}

	for _, a := range algs {
		fmt.Println(a.Name, a.Driver, a.Module, a.Priority)

		// Temporary: remove when all types are implemented.
		if a.Type != nil {
			fmt.Printf("\t %s: ", a.Type.Type())
		}

		switch a := a.Type.(type) {
		case *cryptonl.Hash:
			fmt.Printf("%d %d\n", a.DigestSize, a.BlockSize)
		case *cryptonl.Cipher:
			fmt.Printf("%d %d/%d\n", a.BlockSize, a.MinKeySize, a.MaxKeySize)
		}
	}
}
