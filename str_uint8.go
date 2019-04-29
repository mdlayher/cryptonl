//+build linux,arm linux,ppc64 linux,ppc64le linux,riscv64

package cryptonl

import "github.com/mdlayher/netlink/nlenc"

// String packing and unpacking functions for architectures which represent
// strings as []uint8 for the Linux kernel crypto API.

func str(s []uint8) string {
	return nlenc.String(s)
}

func pack(s string) [64]uint8 {
	return []uint8(s)
}
