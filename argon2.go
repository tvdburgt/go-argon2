package argon2

// #cgo CFLAGS: -I${SRCDIR}/libargon2/src
// #cgo LDFLAGS: -L${SRCDIR}/libargon2 -l:libargon2.a
// #include <stdlib.h>
// #include "argon2.h"
import "C"

import (
	"bytes"
	"crypto/subtle"
	"strings"
	"unsafe"
)

const (
	ModeArgon2d int = C.Argon2_d
	ModeArgon2i int = C.Argon2_i
)

const (
	FlagClearPassword int = C.ARGON2_FLAG_CLEAR_PASSWORD
	FlagClearSecret   int = C.ARGON2_FLAG_CLEAR_SECRET
	FlagClearMemory   int = C.ARGON2_FLAG_CLEAR_MEMORY
)

type Context struct {
	Iterations  int // number of iterations (t_cost)
	Memory      int // memory usage in KiB (m_cost)
	Parallelism int // number of parallel threads

	HashLen int // desired hash output length
	Mode    int // ModeArgon2d or ModeArgon2i

	Secret         []byte // optional
	AssociatedData []byte // optional
	Flags          int    // optional
}

// NewContext initializes a new Argon2 context with reasonable defaults.
func NewContext() *Context {
	return &Context{
		Iterations:  3,
		Memory:      1 << 12, // 4 MiB
		Parallelism: 1,
		HashLen:     32,
		Mode:        ModeArgon2i,
	}
}

// init initializes an argon2_context struct instance and allocates a hash
// slice.
func (ctx *Context) init(password, salt []byte) (c *C.argon2_context, hash []byte, err error) {
	if len(password) == 0 {
		return nil, nil, ErrPassword
	}
	if len(salt) == 0 {
		return nil, nil, ErrSalt
	}

	hash = make([]byte, ctx.HashLen)

	c = &C.argon2_context{
		out:     (*C.uint8_t)(&hash[0]),
		outlen:  C.uint32_t(ctx.HashLen),
		pwd:     (*C.uint8_t)(&password[0]),
		pwdlen:  C.uint32_t(len(password)),
		salt:    (*C.uint8_t)(&salt[0]),
		saltlen: C.uint32_t(len(salt)),
		t_cost:  C.uint32_t(ctx.Iterations),
		m_cost:  C.uint32_t(ctx.Memory),
		lanes:   C.uint32_t(ctx.Parallelism),
		threads: C.uint32_t(ctx.Parallelism),
		flags:   C.ARGON2_DEFAULT_FLAGS,
	}

	if len(ctx.Secret) > 0 {
		c.secret = (*C.uint8_t)(&ctx.Secret[0])
		c.secretlen = C.uint32_t(len(ctx.Secret))
	}

	if len(ctx.AssociatedData) > 0 {
		c.ad = (*C.uint8_t)(&ctx.AssociatedData[0])
		c.adlen = C.uint32_t(len(ctx.AssociatedData))
	}

	if ctx.Flags != 0 {
		c.flags = C.uint32_t(ctx.Flags)
	}

	return
}

func (ctx *Context) hash(password, salt []byte) ([]byte, error) {
	c, hash, err := ctx.init(password, salt)
	if err != nil {
		return nil, err
	}

	result := C.argon2_core(c, C.argon2_type(ctx.Mode))
	if result != C.ARGON2_OK {
		return nil, Error(result)
	}

	return hash, nil
}

func Hash(ctx *Context, password, salt []byte) ([]byte, error) {
	if ctx == nil {
		return nil, ErrContext
	}

	return ctx.hash(password, salt)
}

func HashEncoded(ctx *Context, password, salt []byte) (string, error) {
	if ctx == nil {
		return "", ErrContext
	}

	c, _, err := ctx.init(password, salt)
	if err != nil {
		return "", err
	}

	s := make([]byte, getEncodedLen(ctx.HashLen, len(salt)))
	result := C.argon2_hash(
		c.t_cost, c.m_cost, c.threads,
		unsafe.Pointer(c.pwd), C.size_t(c.pwdlen),
		unsafe.Pointer(c.salt), C.size_t(c.saltlen),
		nil, C.size_t(c.outlen),
		(*C.char)(unsafe.Pointer(&s[0])), C.size_t(len(s)),
		C.argon2_type(ctx.Mode))

	if result != C.ARGON2_OK {
		return "", Error(result)
	}

	// Strip trailing null byte(s)
	s = bytes.TrimRight(s, "\x00")
	return string(s), nil
}

func Verify(ctx *Context, hash, password, salt []byte) (bool, error) {
	if ctx == nil {
		return false, ErrContext
	}
	if len(hash) == 0 {
		return false, ErrHash
	}

	hash2, err := ctx.hash(password, salt)
	if err != nil {
		return false, err
	}

	// verify_i/verify_d doesn't seem to be using constant time comparison...
	return subtle.ConstantTimeCompare(hash, hash2) == 1, nil
}

func VerifyEncoded(s string, password []byte) (bool, error) {
	mode, err := getMode(s)
	if err != nil {
		return false, err
	}

	cs := C.CString(s)
	defer C.free(unsafe.Pointer(cs))

	result := C.argon2_verify(
		cs,
		unsafe.Pointer(&password[0]),
		C.size_t(len(password)),
		C.argon2_type(mode))

	if result == C.ARGON2_OK {
		return true, nil
	}

	// argon2_verify always seems to return an error in this case...
	return false, Error(result)
}

// getMode tries to extract the mode from an Argon2 encoded string.
func getMode(s string) (int, error) {
	switch {
	case strings.HasPrefix(s, "$argon2d"):
		return ModeArgon2d, nil
	case strings.HasPrefix(s, "$argon2i"):
		return ModeArgon2i, nil
	default:
		return -1, ErrDecodingFail
	}
}

// getEncodedLen calculates the maximum number of bytes required for an encoded
// string.
func getEncodedLen(hashLen, saltLen int) int {
	const mlen = 12
	const tlen = 7
	const plen = 7

	total := len("$argon2i") + mlen + tlen + plen
	total += getBase64Len(hashLen) + 1
	total += getBase64Len(saltLen) + 1

	return total + 1 // include null byte
}

func getBase64Len(n int) int {
	return (n + 2) / 3 * 4 // based on base64.EncodedLen
}
