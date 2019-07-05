frand
-----

[![GoDoc](https://godoc.org/lukechampine.com/frand?status.svg)](https://godoc.org/lukechampine.com/frand)
[![Go Report Card](http://goreportcard.com/badge/lukechampine.com/frand)](https://goreportcard.com/report/lukechampine.com/frand)

```
go get lukechampine.com/frand
```

`frand` is a fast userspace CSPRNG. The RNG produces its output from
[ChaCha](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant) keystreams. The
initial cipher key is derived from system entropy (via `crypto/rand`). Since
only one syscall is required to initialize the RNG, `frand` can generate
randomness much faster than `crypto/rand`, and generation cannot fail.

`frand` is based on [`fastrand`](https://gitlab.com/NebulousLabs/fastrand), but
generates its randomness from the ChaCha cipher instead of repeated BLAKE-2b
hashing. `frand` is 5-10x faster than `fastrand` and 5-100x faster than
`crypto/rand`. Its speed makes it a viable replacement even for `math/rand` when
maximum performance is desired.


## Misconceptions


**Don't roll your own crypto!**

There isn't any novel crypto here; we're just reading the output of a ChaCha
stream. The only non-trivial part is the key erasure: we overwrite the key with
the cipher output after each use, which provides forward secrecy. djb describes
the construction [here](https://blog.cr.yp.to/20170723-random.html), noting that
it "certainly isn't new."


**The output won't be as random as /dev/random!**

`/dev/random`, `/dev/urandom`, and `getentropy(2)` all generate their output the
same way `frand` does: from a ChaCha keystream seeded with 256 bits of
unpredictable entropy. Without access to the RNG state, it is not possible for
an attacker to distinguish between output from `frand` and output from your OS's
RNG.


**The RNG state can be read or written with side-channel attacks!**

Yes, the key resides in memory, so it could be read using an attack like
[RAMBleed](https://rambleed.com) or written using an attack like
[RowHammer](https://en.wikipedia.org/wiki/Row_hammer). But consider that this
applies to every other piece of secret data in your program as well: session
keys, encyption keys, passwords, etc. If attackers can directly read and write
your RAM, you likely have bigger problems to contend with.


**CSPRNGs don't need to be fast!**

If CSPRNGs are slow, people will only use them to generate key material, and
will use less secure PRNGs like `math/rand` for everything else. There is no
downside to using a fast CSPRNG for these applications instead, and considerable
upside (namely, better protection against unforeseen attacks).

Another perspective: when programmers today need randomness, they have to decide
between "strong but slow" randomness and "weak but fast" randomness. If there
were a "strong and fast" option, there would be no need to make such a decision,
and thus no risk of introducing a vulnerability.


## Benchmarks


| Benchmark                | `crypto/rand` | `fastrand` | `frand`    | `math` (insecure) |
|--------------------------|---------------|------------|------------|-------------------|
| Read (32b)               | 59 MB/s       | 215 MB/s   | 964 MB/s   | 634.21 MB/s       |
| Read (32b, concurrent)   | 70 MB/s       | 615 MB/s   | 3566 MB/s  | 198.97 MB/s       |
| Read (512kb)             | 239 MB/s      | 452 MB/s   | 5094 MB/s  | 965.85 MB/s       |
| Read (512kb, concurrent) | 191 MB/s      | 1599 MB/s  | 19665 MB/s | 958.01 MB/s       |
| Intn (n =~ 4e18)         | 725 ns/op     | 210 ns/op  | 45 ns/op   | 20 ns/op          |
| BigIntn (n = 2^630)      | 1013 ns/op    | 468 ns/op  | 223 ns/op  | 295 ns/op         |
| Perm (n = 32)            | 17197 ns/op   | 5021 ns/op | 954 ns/op  | 789 ns/op         |

Benchmark details:

"Concurrent" means the `Read` function was called in parallel from 64 goroutines.

`Intn` was benchmarked with n = 2^62 + 1, which maximizes the number of expected
retries required to remove bias. The number of expected retries is 1.333.
