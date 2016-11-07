# go-argon2

[![GoDoc](https://godoc.org/github.com/tvdburgt/go-argon2?status.svg)](https://godoc.org/github.com/tvdburgt/go-argon2)

Go bindings for the reference C implementation of
[Argon2](https://github.com/P-H-C/phc-winner-argon2), the winner of the
[Password Hash Competition](https://password-hashing.net).

## Installation

```
$ go get -d github.com/tvdburgt/go-argon2
```

This package depends on `libargon2`, specifically `libargon2.so` and `argon2.h`.
Make sure the library files are available in `/usr`:


```
$ git clone https://github.com/P-H-C/phc-winner-argon2.git argon2
$ cd argon2
$ git checkout 20161029
$ sudo make install
```

Test everything is installed correctly:

```
$ cd $GOCODE/src/github.com/tvdburgt/go-argon2/
$ go test
```

## Usage
### Raw hash with default configuration

```go
hash, err := argon2.Hash(argon2.NewContext(), []byte("password"), []byte("somesalt"))
if err != nil {
	log.Fatal(err)
}

fmt.Printf("%x\n", hash)
```

### Encoded hash with custom configuration

```go
ctx := &argon2.Context{
	Iterations:  5,
	Memory:      1 << 16,
	Parallelism: 2,
	HashLen:     32,
	Mode:        argon2.ModeArgon2i,
	Version:     argon2.Version13,
}

s, err := argon2.HashEncoded(ctx, []byte("password"), []byte("somesalt"))
if err != nil {
	log.Fatal(err)
}

fmt.Println(s)
```
