//+build linux

package cryptonl

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

func Test_parseAlgorithmError(t *testing.T) {
	// Produces bad output for the specified netlink attribute.
	encodeBad := func(typ uint16) []byte {
		b := make([]byte, sizeofCryptoUserAlg)

		ae := netlink.NewAttributeEncoder()
		ae.Do(typ, func() ([]byte, error) {
			return []byte{0xff}, nil
		})

		ab, err := ae.Encode()
		if err != nil {
			panicf("failed to encode attributes: %v", err)
		}

		return append(b, ab...)
	}

	tests := []struct {
		name string
		b    []byte
	}{
		{
			name: "crypto_user_alg",
			b:    []byte{0xff},
		},
		{
			name: "crypto_report_cipher",
			b:    encodeBad(unix.CRYPTOCFGA_REPORT_CIPHER),
		},
		{
			name: "crypto_report_hash",
			b:    encodeBad(unix.CRYPTOCFGA_REPORT_HASH),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseAlgorithm(tt.b)
			if err == nil {
				t.Fatal("expected an error, but none occurred")
			}

			t.Logf("OK err: %v", err)
		})
	}
}

func TestIntegrationConnAlgorithms(t *testing.T) {
	c, err := Dial()
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer c.Close()

	algs, err := c.Algorithms()
	if err != nil {
		t.Fatalf("failed to get algorithms: %v", err)
	}

	// Look for specific algorithms with known qualities.
	const (
		sha1Name   = "sha1"
		sha1Type   = "shash"
		sha1Digest = 20
	)

	var sha1Found bool

	for _, a := range algs {
		switch a.Name {
		case sha1Name:
			if diff := cmp.Diff(sha1Type, a.Type.Type()); diff != "" {
				t.Fatalf("unexpected SHA-1 hash type (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(sha1Digest, a.Type.(*Hash).DigestSize); diff != "" {
				t.Fatalf("unexpected SHA-1 digest size (-want +got):\n%s", diff)
			}

			sha1Found = true
		}
	}

	if !sha1Found {
		t.Fatal("did not find SHA-1 hash implementation")
	}
}

func TestConnAlgorithms(t *testing.T) {
	var (
		sha1h = &Hash{
			BlockSize:  64,
			DigestSize: 20,
			typer:      "shash",
		}

		sha1 = &Algorithm{
			Name:     "sha1",
			Driver:   "sha1-generic",
			Module:   "kernel",
			Priority: 0,
			Type:     sha1h,
		}

		aesc = &Cipher{
			BlockSize:  16,
			MinKeySize: 16,
			MaxKeySize: 32,
			typer:      "cipher",
		}

		aes = &Algorithm{
			Name:     "aes",
			Driver:   "aes-aesni",
			Module:   "aesni_intel",
			Priority: 300,
			Type:     aesc,
		}
	)

	c, done := testConn(t, []response{
		{
			UserAlg: unix.CryptoUserAlg{
				Name:        pack(sha1.Name),
				Driver_name: pack(sha1.Driver),
				Module_name: pack(sha1.Module),
			},
			Priority: uint32(sha1.Priority),
			Alg: unix.CryptoReportHash{
				Type:       pack(sha1.Type.Type()),
				Blocksize:  uint32(sha1h.BlockSize),
				Digestsize: uint32(sha1h.DigestSize),
			},
		},
		{
			UserAlg: unix.CryptoUserAlg{
				Name:        pack(aes.Name),
				Driver_name: pack(aes.Driver),
				Module_name: pack(aes.Module),
			},
			Priority: uint32(aes.Priority),
			Alg: unix.CryptoReportCipher{
				Type:        pack(aes.Type.Type()),
				Blocksize:   uint32(aesc.BlockSize),
				Min_keysize: uint32(aesc.MinKeySize),
				Max_keysize: uint32(aesc.MaxKeySize),
			},
		},
	})
	defer done()

	algs, err := c.Algorithms()
	if err != nil {
		t.Fatalf("failed to get algorithms: %v", err)
	}

	if diff := cmp.Diff(2, len(algs)); diff != "" {
		t.Fatalf("unexpected number of algorithms (-want +got):\n%s", diff)
	}

	allow := cmp.AllowUnexported(
		Cipher{},
		Hash{},
	)

	if diff := cmp.Diff(sha1, algs[0], allow); diff != "" {
		t.Fatalf("unexpected SHA-1 hash algorithm (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff(aes, algs[1], allow); diff != "" {
		t.Fatalf("unexpected AES cipher algorithm (-want +got):\n%s", diff)
	}
}

// A response contains information returned by the Linux kernel crypto API.
type response struct {
	UserAlg  unix.CryptoUserAlg
	Priority uint32

	// Could be any of unix.CRYPTO_REPORT_*.
	Alg interface{}
}

// testConn sets up a Conn and serves data from res to methods invoked on Conn.
func testConn(t *testing.T, res []response) (*Conn, func()) {
	t.Helper()

	c := &Conn{
		c: nltest.Dial(func(req []netlink.Message) ([]netlink.Message, error) {
			if diff := cmp.Diff(1, len(req)); diff != "" {
				t.Fatalf("unexpected number of request messages (-want +got):\n%s", diff)
			}

			// Return many messages in response to the single request.
			h := netlink.Header{
				Sequence: req[0].Header.Sequence,
				PID:      req[0].Header.PID,
			}

			msgs := make([]netlink.Message, 0, len(res))
			for _, r := range res {
				msgs = append(msgs, netlink.Message{
					Header: h,
					Data:   mustEncodeResponse(r),
				})
			}

			return msgs, nil
		}),
	}

	return c, func() {
		if err := c.Close(); err != nil {
			t.Fatalf("failed to close: %v", err)
		}
	}
}

// mustEncodeResponse packs the fields of r into a byte slice which matches
// the format produced by the Linux kernel crypto API.
func mustEncodeResponse(r response) []byte {
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(unix.CRYPTOCFGA_PRIORITY_VAL, r.Priority)

	// Pack individual algorithm type structures as raw bytes, using the
	// appropriate attribute type for each.
	//
	// It'd be nice to collapse the unsafe pointer conversions into a single
	// block, but we cannot use a non-constant array size when performing
	// the conversion from a structure to raw bytes.
	switch a := r.Alg.(type) {
	case unix.CryptoReportCipher:
		ae.Do(unix.CRYPTOCFGA_REPORT_CIPHER, func() ([]byte, error) {
			return (*(*[sizeofCryptoReportCipher]byte)(unsafe.Pointer(&a)))[:], nil
		})
	case unix.CryptoReportHash:
		ae.Do(unix.CRYPTOCFGA_REPORT_HASH, func() ([]byte, error) {
			return (*(*[sizeofCryptoReportHash]byte)(unsafe.Pointer(&a)))[:], nil
		})
	default:
		panicf("unhandled r.Alg parameter type: %T", r.Alg)
	}

	ab, err := ae.Encode()
	if err != nil {
		panicf("failed to encode attributes: %v", err)
	}

	// Pack the crypto_user_alg structure ahead of the netlink attributes; the
	// same format produced by the kernel.
	b := *(*[sizeofCryptoUserAlg]byte)(unsafe.Pointer(&r.UserAlg))

	return append(b[:], ab...)
}

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}
