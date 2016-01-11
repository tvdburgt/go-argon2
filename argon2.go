package argon2

// #cgo CFLAGS: -I${SRCDIR}/libargon2/src
// #cgo LDFLAGS: -L${SRCDIR}/libargon2 -largon2
// #include "argon2.h"
import "C"

import (
	"errors"
	"fmt"
)

type Mode int
type Flags int

// Error propagated from Argon2.
// See argon2.h for a list of error codes.
type Argon2Error int

const (
	ModeArgon2d Mode = C.Argon2_d
	ModeArgon2i Mode = C.Argon2_i
)

const (
	FlagClearPassword Flags = C.ARGON2_FLAG_CLEAR_PASSWORD
	FlagClearSecret   Flags = C.ARGON2_FLAG_CLEAR_SECRET
	FlagClearMemory   Flags = C.ARGON2_FLAG_CLEAR_MEMORY
)

type Context struct {
	Iterations     int    // number of iterations (t_cost)
	Memory         int    // memory usage in KiB (m_cost)
	Parallelism    int    // number of parallel threads
	HashLen        int    // length of hash output
	Mode           Mode   // argon2 mode
	Secret         []byte // optional
	AssociatedData []byte // optional
	Flags          Flags  // optional

	hash     []byte
	password []byte
	salt     []byte
}

func (e Argon2Error) Error() string {
	msg := C.error_message(C.int(e))
	return fmt.Sprintf("argon2: %s", C.GoString(msg))
}

// Constructs argon2_context from underlying context
func (ctx *Context) context() (*C.argon2_context, error) {
	if len(ctx.password) == 0 {
		return nil, errors.New("argon2: password is nil or empty")
	}
	if len(ctx.salt) == 0 {
		return nil, errors.New("argon2: salt is nil or empty")
	}

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

	return c, nil
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
	ctx.hash = make([]byte, ctx.HashLen)
	ctx.password = password
	ctx.salt = salt

	c, err := ctx.context()
	if err != nil {
		return nil, err
	}

	result := C.argon2_core(c, C.argon2_type(ctx.Mode))
	if result != C.ARGON2_OK {
		return nil, Argon2Error(result)
	}

	return ctx.hash, nil
}

func (ctx *Context) Verify(hash, password, salt []byte) (bool, error) {
	if hash == nil || len(hash) == 0 {
		return false, errors.New("argon2: hash is nil or empty")
	}

	var result C.int
	ctx.password = password
	ctx.salt = salt

	c, err := ctx.context()
	if err != nil {
		return false, err
	}

	switch ctx.Mode {
	case ModeArgon2i:
		result = C.verify_i(c, C.CString(string(hash)))
	case ModeArgon2d:
		result = C.verify_d(c, C.CString(string(hash)))
	default:
		return false, errors.New("argon2: invalid mode")
	}

	if result == 1 {
		return true, nil
	}

	if result == C.ARGON2_OK {
		return false, nil
	}

	return false, Argon2Error(result)
}
