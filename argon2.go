// Package argon2 provides low-level bindings for the Argon2 hashing library:
// libargon2. Argon2 specifies two versions: Argon2i and Argon2d. Argon2i is
// useful for protection against side-channel attacks, while Argon2d provides
// the highest resistance against GPU cracking attacks.
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

// Hash hashes a password given a salt and an initialized Argon2 context. It
// returns the calculated hash as an output of raw bytes.
func Hash(ctx *Context, password, salt []byte) ([]byte, error) {
	if ctx == nil {
		return nil, ErrContext
	}

	return ctx.hash(password, salt)
}

// HashEncoded hashes a password and produces a crypt-like encoded string.
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

// Verify verifies an Argon2 hash against a plaintext password.
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

	// The raw verify functions in libargon2 don't seem to be using a
	// constant time comparison. Resort to crypto/subtle for now.
	return subtle.ConstantTimeCompare(hash, hash2) == 1, nil
}

// VerifyEncoded verifies an encoded Argon2 hash s against a plaintext password.
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
