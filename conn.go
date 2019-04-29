package cryptonl

import "github.com/mdlayher/netlink"

// Constants copied from x/sys/unix to avoid creating more platform-specific
// shim code.
const (
	netlinkCrypto   = 0x15 // unix.NETLINK_CRYPTO
	cryptoMsgGetalg = 0x13 // unix.CRYPTO_MSG_GETALG
)

// A Conn is a connection to the Linux kernel crypto API's netlink interface.
type Conn struct {
	c *netlink.Conn
}

// Dial dials a new connection to the Linux kernel crypto API's netlink
// interface.
func Dial() (*Conn, error) {
	c, err := netlink.Dial(netlinkCrypto, nil)
	if err != nil {
		return nil, err
	}

	return &Conn{c: c}, nil
}

// Close closes the connection.
func (c *Conn) Close() error {
	return c.c.Close()
}

// Algorithms retrieves all algorithms registered with the Linux kernel crypto
// API.
func (c *Conn) Algorithms() ([]*Algorithm, error) {
	msgs, err := c.c.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  cryptoMsgGetalg,
			Flags: netlink.Request | netlink.Acknowledge | netlink.Dump,
		},
	})
	if err != nil {
		return nil, err
	}

	algs := make([]*Algorithm, 0, len(msgs))
	for _, m := range msgs {
		a, err := parseAlgorithm(m.Data)
		if err != nil {
			return nil, err
		}

		algs = append(algs, a)
	}

	return algs, nil
}
