package frand // import "lukechampine.com/frand"

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"math/big"
	"strconv"
	"sync"

	"github.com/aead/chacha20/chacha"
)

func erase(p []byte) {
	// compiles to memclr
	for i := range p {
		p[i] = 0
	}
}

// An RNG is a cryptographically-strong RNG constructed from the ChaCha stream
// cipher.
type RNG struct {
	buf    []byte
	n      int
	rounds int
}

func (r *RNG) reseed() {
	chacha.XORKeyStream(r.buf, r.buf, make([]byte, chacha.NonceSize), r.buf[:chacha.KeySize], r.rounds)
	r.n = chacha.KeySize
}

// Read fills b with random data. It always returns len(b), nil.
func (r *RNG) Read(b []byte) (int, error) {
	if len(b) > len(r.buf) {
		// for large b, avoid reseeding multiple times; instead, reseed once to
		// generate a temporary key, then write directly into b using that key
		r.reseed()
		tmpKey := r.buf[r.n : r.n+chacha.KeySize]
		chacha.XORKeyStream(b, b, make([]byte, chacha.NonceSize), tmpKey, r.rounds)
		erase(tmpKey)
		r.n += len(tmpKey)
		return len(b), nil
	}
	// for small b, read from the buffer of previously-generated entropy
	n := 0
	for n < len(b) {
		if r.n == len(r.buf) {
			r.reseed()
		}
		c := copy(b[n:], r.buf[r.n:])
		erase(r.buf[r.n : r.n+c])
		n += c
		r.n += c
	}
	return len(b), nil
}

// Bytes is a helper function that allocates and returns n bytes of random data.
func (r *RNG) Bytes(n int) []byte {
	b := make([]byte, n)
	r.Read(b)
	return b
}

// Uint64n returns a uniform random uint64 in [0,n). It panics if n == 0.
func (r *RNG) Uint64n(n uint64) uint64 {
	if n == 0 {
		panic("fastrand: argument to Uint64n is 0")
	}
	// To eliminate modulo bias, keep selecting at random until we fall within
	// a range that is evenly divisible by n.
	// NOTE: since n is at most math.MaxUint64, max is minimized when:
	//    n = math.MaxUint64/2 + 1 -> max = math.MaxUint64 - math.MaxUint64/2
	// This gives an expected 2 tries before choosing a value < max.
	max := math.MaxUint64 - math.MaxUint64%n
	b := make([]byte, 8)
again:
	r.Read(b)
	i := binary.LittleEndian.Uint64(b)
	if i >= max {
		goto again
	}
	return i % n
}

// Intn returns a uniform random int in [0,n). It panics if n <= 0.
func (r *RNG) Intn(n int) int {
	if n <= 0 {
		panic("fastrand: argument to Intn is <= 0: " + strconv.Itoa(n))
	}
	// NOTE: since n is at most math.MaxUint64/2, max is minimized when:
	//    n = math.MaxUint64/4 + 1 -> max = math.MaxUint64 - math.MaxUint64/4
	// This gives an expected 1.333 tries before choosing a value < max.
	return int(r.Uint64n(uint64(n)))
}

// BigIntn returns a uniform random *big.Int in [0,n). It panics if n <= 0.
func (r *RNG) BigIntn(n *big.Int) *big.Int {
	i, _ := rand.Int(r, n)
	return i
}

// Perm returns a random permutation of the integers [0,n). It panics if n < 0.
func (r *RNG) Perm(n int) []int {
	m := make([]int, n)
	for i := 1; i < n; i++ {
		j := r.Intn(i + 1)
		m[i] = m[j]
		m[j] = i
	}
	return m
}

// New returns a new RNG instance seeded with entropy from crypto/rand.
func New() *RNG {
	seed := make([]byte, chacha.KeySize)
	n, err := rand.Read(seed)
	if err != nil || n != len(seed) {
		panic("not enough system entropy to seed cipher")
	}
	// ChaCha12 is a good balance of security and performance. ChaCha8 is
	// significantly weaker without being much faster; ChaCha20 is significant
	// slower without being much stronger.
	return NewCustom(seed, 1024, 12)
}

// NewCustom returns a new RNG instance seeded with the provided entropy and
// using the specified buffer size and number of ChaCha rounds. It panics if
// len(seed) != 32 or if rounds is not 8, 12 or 20.
func NewCustom(seed []byte, bufsize int, rounds int) *RNG {
	r := &RNG{
		buf:    make([]byte, chacha.KeySize+bufsize),
		rounds: rounds,
	}
	copy(r.buf, seed)
	r.reseed()
	return r
}

// Global versions of each RNG method, leveraging a pool of RNGs.

var rngpool = sync.Pool{
	New: func() interface{} {
		return New()
	},
}

// Read fills b with random data. It always returns len(b), nil.
func Read(b []byte) (int, error) {
	r := rngpool.Get().(*RNG)
	n, err := r.Read(b)
	rngpool.Put(r)
	return n, err
}

// Bytes is a helper function that allocates and returns n bytes of random data.
func Bytes(n int) []byte {
	r := rngpool.Get().(*RNG)
	b := r.Bytes(n)
	rngpool.Put(r)
	return b
}

// Uint64n returns a uniform random uint64 in [0,n). It panics if n == 0.
func Uint64n(n uint64) uint64 {
	r := rngpool.Get().(*RNG)
	i := r.Uint64n(n)
	rngpool.Put(r)
	return i
}

// Intn returns a uniform random int in [0,n). It panics if n <= 0.
func Intn(n int) int {
	r := rngpool.Get().(*RNG)
	i := r.Intn(n)
	rngpool.Put(r)
	return i
}

// BigIntn returns a uniform random *big.Int in [0,n). It panics if n <= 0.
func BigIntn(n *big.Int) *big.Int {
	r := rngpool.Get().(*RNG)
	i := r.BigIntn(n)
	rngpool.Put(r)
	return i
}

// Perm returns a random permutation of the integers [0,n). It panics if n < 0.
func Perm(n int) []int {
	r := rngpool.Get().(*RNG)
	i := r.Perm(n)
	rngpool.Put(r)
	return i
}

// Reader is a global, shared instance of a cryptographically strong pseudo-
// random generator. Reader is safe for concurrent use by multiple goroutines.
var Reader rngReader

type rngReader struct{}

func (rngReader) Read(b []byte) (int, error) {
	Read(b)
	return len(b), nil
}
