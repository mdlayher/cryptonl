//+build linux,!arm,!ppc64,!ppc64le,!riscv64

package cryptonl

import (
	"unsafe"

	"github.com/mdlayher/netlink/nlenc"
)

// String packing and unpacking functions for architectures which represent
// strings as []int8 for the Linux kernel crypto API.

func str(s []int8) string {
	return nlenc.String(*(*[]uint8)(unsafe.Pointer(&s)))
}

func pack(s string) [64]int8 {
	var out [64]byte
	copy(out[:], s)

	return *(*[64]int8)(unsafe.Pointer(&out))
}
