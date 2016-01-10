package argon2

// #cgo CFLAGS: -I${SRCDIR}/libargon2/src
// #cgo LDFLAGS: -L${SRCDIR}/libargon2 -largon2
// #include "argon2.h"
import "C"

import (
	"errors"
	"fmt"
)

type Mode C.argon2_type

const (
	ModeArgon2d Mode = C.Argon2_d
	ModeArgon2i Mode = C.Argon2_i
)

type Context struct {
	Iterations     int    // number of iterations (t_cost)
	Memory         int    // memory usage in KiB (m_cost)
	Parallelism    int    // number of parallel threads
	Secret         []byte // optional
	AssociatedData []byte // optional
	HashLen        int    // length of hash output
	Mode           Mode   // argon2.ModeArgon2d or argon2.ModeArgon2i

	hash     []byte
	password []byte
	salt     []byte
}

// Constructs argon2_context from underlying context
func (ctx *Context) context() *C.argon2_context {
	c := &C.argon2_context{
		out:     (*C.uint8_t)(&ctx.hash[0]),
		outlen:  C.uint32_t(ctx.HashLen),
		pwd:     (*C.uint8_t)(&ctx.password[0]),
		pwdlen:  C.uint32_t(len(ctx.password)),
		salt:    (*C.uint8_t)(&ctx.salt[0]),
		saltlen: C.uint32_t(len(ctx.salt)),
		t_cost:  C.uint32_t(ctx.Iterations),
		m_cost:  C.uint32_t(ctx.Memory),
		lanes:   C.uint32_t(ctx.Parallelism),
		threads: C.uint32_t(ctx.Parallelism),
		flags:   C.ARGON2_DEFAULT_FLAGS,
	}

	if ctx.Secret != nil {
		c.secret = (*C.uint8_t)(&ctx.Secret[0])
		c.secretlen = C.uint32_t(len(ctx.Secret))
	}

	if ctx.AssociatedData != nil {
		c.ad = (*C.uint8_t)(&ctx.AssociatedData[0])
		c.adlen = C.uint32_t(len(ctx.AssociatedData))
	}

	return c
}

func NewContext() *Context {
	return &Context{
		Iterations:  3,
		Memory:      1 << 12, // 4 MiB
		Parallelism: 1,
		HashLen:     32,
		Mode:        ModeArgon2i,
	}
}

func (ctx *Context) Hash(password, salt []byte) ([]byte, error) {
	if password == nil || len(password) == 0 {
		return nil, errors.New("argon2: password is nil or empty")
	}

	if salt == nil || len(salt) == 0 {
		return nil, errors.New("argon2: salt is nil or empty")
	}

	ctx.hash = make([]byte, ctx.HashLen)
	ctx.password = password
	ctx.salt = salt
	result := C.argon2_core(ctx.context(), C.argon2_type(ctx.Mode))

	if result != C.ARGON2_OK {
		return nil, fmt.Errorf("argon2: operation failed (error code: %d)", result)
	}

	return ctx.hash, nil
}

func (ctx *Context) Verify(hash, password, salt []byte) (bool, error) {
	if hash == nil || len(hash) == 0 {
		return false, errors.New("argon2: hash is nil or empty")
	}
	if password == nil || len(password) == 0 {
		return false, errors.New("argon2: password is nil or empty")
	}
	if salt == nil || len(salt) == 0 {
		return false, errors.New("argon2: salt is nil or empty")
	}

	var result C.int
	ctx.password = password
	ctx.salt = salt

	switch ctx.Mode {
	case ModeArgon2i:
		result = C.verify_i(ctx.context(), C.CString(string(hash)))
	case ModeArgon2d:
		result = C.verify_d(ctx.context(), C.CString(string(hash)))
	default:
		return false, errors.New("argon2: invalid mode")
	}

	// TODO: additional check for error codes
	return result == 1, nil
}
