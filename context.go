package argon2

// #include "argon2.h"
import "C"

// Context represents a structure that holds all static configuration values,
// used to parameterize an Argon2 hash function.
type Context struct {
	Iterations     int    // number of iterations (t_cost)
	Memory         int    // memory usage in KiB (m_cost)
	Parallelism    int    // number of parallel threads
	HashLen        int    // desired hash output length
	Mode           int    // ModeArgon2d or ModeArgon2i
	Secret         []byte // optional (not used by default)
	AssociatedData []byte // optional (not used by default)
	Flags          int    // optional (default is FlagClearMemory)
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
