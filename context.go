package argon2

// #cgo CFLAGS: -I/usr/include
// #include <argon2.h>
// #include "wrapper.h"
import "C"

// Context represents a structure that holds all static configuration values,
// used to parameterize an Argon2 hash function.
type Context struct {
	Iterations     int    // number of iterations (t_cost)
	Memory         int    // memory usage in KiB (m_cost)
	Parallelism    int    // number of parallel threads
	HashLen        int    // desired hash output length
	Mode           int    // ModeArgon2d, ModeArgon2i, or ModeArgon2id
	Version        int    // Version10 or Version13 (aka VersionDefault)
	Secret         []byte // optional (not used by default)
	AssociatedData []byte // optional (not used by default)
	Flags          int    // optional (default is FlagDefault)
}

// NewContext initializes a new Argon2 context with reasonable defaults.
// allows the mode to be set as an optional paramter
func NewContext(mode ...int) *Context {
	context := &Context{
		Iterations:  3,
		Memory:      1 << 12, // 4 MiB
		Parallelism: 1,
		HashLen:     32,
		Mode:        ModeArgon2i,
		Version:     VersionDefault,
	}
	if len(mode) >= 1 {
		context.Mode = mode[0]
	}
	return context
}

// hash password and salt
func (ctx *Context) hash(password []byte, salt []byte) ([]byte, error) {

	if len(password) == 0 {
		return nil, ErrPassword
	}
	if len(salt) == 0 {
		return nil, ErrSalt
	}

	hash := make([]byte, ctx.HashLen)

	// optional secret
	secret := (*C.uint8_t)(nil)
	if len(ctx.Secret) > 0 {
		secret = (*C.uint8_t)(&ctx.Secret[0])
	}

	// optional associated data
	associatedData := (*C.uint8_t)(nil)
	if len(ctx.AssociatedData) > 0 {
		associatedData = (*C.uint8_t)(&ctx.AssociatedData[0])
	}

	// optional flags
	flags := FlagDefault
	if ctx.Flags != 0 {
		flags = ctx.Flags
	}

	// wrapper to overcome go pointer passing limitations
	result := C.argon2_wrapper(
		(*C.uint8_t)(&hash[0]), C.uint32_t(ctx.HashLen),
		(*C.uint8_t)(&password[0]), C.uint32_t(len(password)),
		(*C.uint8_t)(&salt[0]), C.uint32_t(len(salt)),
		secret, C.uint32_t(len(ctx.Secret)),
		associatedData, C.uint32_t(len(ctx.AssociatedData)),
		C.uint32_t(ctx.Iterations),
		C.uint32_t(ctx.Memory),
		C.uint32_t(ctx.Parallelism),
		C.uint32_t(ctx.Parallelism),
		C.uint32_t(ctx.Version),
		nil, nil,
		C.uint32_t(flags),
		C.argon2_type(ctx.Mode))

	if result != C.ARGON2_OK {
		return nil, Error(result)
	}

	return hash, nil
}
