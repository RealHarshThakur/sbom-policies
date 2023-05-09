//go:build ignore
// +build ignore

package main

import (
	"os"

	"github.com/magefile/mage/mage"
)

// Zero install option.
// Usage example:
//
//	go run magefiles/mage.go tes
func main() { os.Exit(mage.Main()) }
