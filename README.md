# go-argon2
Go bindings for the reference C implementation of
[Argon2](https://github.com/P-H-C/phc-winner-argon2), the winner of the Password
Hash Competition. See
[godoc.org](https://godoc.org/github.com/tvdburgt/go-argon2) for more
information.

## Installation
This package depends on `libargon2`. If it's already available on your system,
you can simply install it directly using `go get`:

```
$ go get github.com/tvdburgt/go-argon2
```

Otherwise, you can get this package without installing it directly and use
library submodule in this repository:
```
$ go get -d github.com/tvdburgt/go-argon2
$ cd $GOPATH/src/github.com/tvdburgt/go-argon2
$ git submodule update --init
$ cd libargon2
$ make && make test
```

## Examples
### Raw hash with default configuration
```go
hash, err := argon2.Hash(argon2.NewContext(), []byte("hunter2"), []byte("somesalt"))
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
}

s, err := argon2.HashEncoded(ctx, []byte("hunter2"), []byte("somesalt"))
if err != nil {
	log.Fatal(err)
}

fmt.Println(s)
```
