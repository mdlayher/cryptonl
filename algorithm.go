package cryptonl

// An Algorithm is an algorithm registered with the Linux kernel crypto API.
type Algorithm struct {
	Name     string
	Driver   string
	Module   string
	Priority int
	Type     Type
}

// A Type is a type of algorithm. Use a type assertion to access additional
// information about a Type.
type Type interface {
	Type() string
}

// A typer is a string which can be embedded to implement Type for algorithms.
type typer string

// Type implements Type.
func (t *typer) Type() string { return string(*t) }

// A Cipher represents a cipher algorithm. *Cipher implements Type.
type Cipher struct {
	BlockSize  int
	MinKeySize int
	MaxKeySize int
	typer
}

// A Hash represents a hash algorithm. *Hash implements Type.
type Hash struct {
	BlockSize  int
	DigestSize int
	typer
}
