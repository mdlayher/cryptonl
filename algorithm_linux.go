//+build linux

package cryptonl

import (
	"fmt"
	"unsafe"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Sizes of C structures returned by the kernel.
const (
	sizeofCryptoUserAlg = int(unsafe.Sizeof(unix.CryptoUserAlg{}))

	sizeofCryptoReportCipher = int(unsafe.Sizeof(unix.CryptoReportCipher{}))
	sizeofCryptoReportHash   = int(unsafe.Sizeof(unix.CryptoReportHash{}))
)

// parseAlgorithm produces an algorithm from a packed byte slice input.
func parseAlgorithm(b []byte) (*Algorithm, error) {
	if len(b) < sizeofCryptoUserAlg {
		return nil, fmt.Errorf("cryptonl: unexpected number of bytes for crypto_user_alg, want: %d, got: %d",
			sizeofCryptoUserAlg, len(b))
	}

	// Attributes occur immediately after the crypto_user_alg structure.
	ad, err := netlink.NewAttributeDecoder(b[sizeofCryptoUserAlg:])
	if err != nil {
		return nil, err
	}

	// crypto_user_alg occurs at the very beginning of the input slice.
	ualg := *(*unix.CryptoUserAlg)(unsafe.Pointer(&b[:sizeofCryptoUserAlg][0]))

	a := Algorithm{
		Name:   str(ualg.Name[:]),
		Driver: str(ualg.Driver_name[:]),
		Module: str(ualg.Module_name[:]),
	}

	// TODO(mdlayher): populate remaining algorithm types and fields.
	for ad.Next() {
		switch ad.Type() {
		case unix.CRYPTOCFGA_PRIORITY_VAL:
			a.Priority = int(ad.Uint32())
		case unix.CRYPTOCFGA_REPORT_CIPHER:
			ad.Do(parseCipher(&a.Type))
		case unix.CRYPTOCFGA_REPORT_HASH:
			ad.Do(parseHash(&a.Type))
		}
	}

	if err := ad.Err(); err != nil {
		return nil, err
	}

	return &a, nil
}

// parseCipher returns a function compatible with a netlink.AttributeDecoder
// which can populate alg with a Cipher.
func parseCipher(alg *Type) func(b []byte) error {
	return func(b []byte) error {
		if len(b) != sizeofCryptoReportCipher {
			return fmt.Errorf("cryptonl: unexpected number of bytes for crypto_report_cipher, want: %d, got: %d",
				sizeofCryptoReportCipher, len(b))
		}

		c := *(*unix.CryptoReportCipher)(unsafe.Pointer(&b[0]))

		*alg = &Cipher{
			BlockSize:  int(c.Blocksize),
			MinKeySize: int(c.Min_keysize),
			MaxKeySize: int(c.Max_keysize),
			typer:      typer(str(c.Type[:])),
		}

		return nil
	}
}

// parseHash returns a function compatible with a netlink.AttributeDecoder
// which can populate alg with a Hash.
func parseHash(alg *Type) func(b []byte) error {
	return func(b []byte) error {
		if len(b) != sizeofCryptoReportHash {
			return fmt.Errorf("cryptonl: unexpected number of bytes for crypto_report_hash, want: %d, got: %d",
				sizeofCryptoReportHash, len(b))
		}

		c := *(*unix.CryptoReportHash)(unsafe.Pointer(&b[0]))

		*alg = &Hash{
			BlockSize:  int(c.Blocksize),
			DigestSize: int(c.Digestsize),
			typer:      typer(str(c.Type[:])),
		}

		return nil
	}
}
