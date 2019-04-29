//+build !linux

package cryptonl

import (
	"fmt"
	"runtime"
)

func parseAlgorithm(b []byte) (*Algorithm, error) {
	return nil, fmt.Errorf("cryptonl: not implemented on %s/%s", runtime.GOOS, runtime.GOARCH)
}
