package argon2

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func ExampleContext_Hash() {
	ctx := NewContext()
	hash, _ := ctx.Hash([]byte("hunter2"), []byte("somesalt"))
	fmt.Printf("%x\n", hash)
	// Output:
	// bfedbc29c9aeb504765c48ec8e7a63f1cdd89f2830e3ab2f26d68a45263ffcae
}

func Example() {
	password := []byte("password")
	salt := make([]byte, 16)
	copy(salt, []byte("somesalt"))

	ctx := Context{
		Iterations:  2,
		Memory:      1 << 16,
		Parallelism: 4,
		HashLen:     32,
		Mode:        ModeArgon2i,
	}

	hash, _ := ctx.Hash(password, salt)
	fmt.Printf("%x\n", hash)
	// Output:
	// 4162f32384d8f4790bd994cb73c83a4a29f076165ec18af3cfdcf10a8d1b9066
}

func TestArgon2i(t *testing.T) {
	ctx := Context{
		Iterations:     3,
		Memory:         1 << 5,
		Parallelism:    4,
		Secret:         bytes.Repeat([]byte{3}, 8),
		AssociatedData: bytes.Repeat([]byte{4}, 12),
		HashLen:        32,
		Mode:           ModeArgon2i,
	}

	password := bytes.Repeat([]byte{1}, 32)
	salt := bytes.Repeat([]byte{2}, 16)
	expected, _ := hex.DecodeString("87aeedd6517ab830cd9765cd8231abb2e647a5dee08f7c05e02fcb763335d0fd")
	hash, err := ctx.Hash(password, salt)

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(expected, hash) {
		t.Fatal("hash output did not match test vector")
	}
}

func TestArgon2d(t *testing.T) {
	ctx := Context{
		Iterations:     3,
		Memory:         1 << 5,
		Parallelism:    4,
		Secret:         bytes.Repeat([]byte{3}, 8),
		AssociatedData: bytes.Repeat([]byte{4}, 12),
		HashLen:        32,
		Mode:           ModeArgon2d,
	}

	password := bytes.Repeat([]byte{1}, 32)
	salt := bytes.Repeat([]byte{2}, 16)
	expected, _ := hex.DecodeString("96a9d4e5a1734092c85e29f410a45914a5dd1f5cbf08b2670da68a0285abf32b")
	hash, err := ctx.Hash(password, salt)

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(expected, hash) {
		t.Fatal("hash output did not match test vector")
	}
}

func TestHashNil(t *testing.T) {
	ctx := NewContext()
	password := make([]byte, 16)
	salt := make([]byte, 16)

	_, err := ctx.Hash(nil, salt)
	if err == nil {
		t.Error("expected err (password = nil)")
	}

	_, err = ctx.Hash(password, nil)
	if err == nil {
		t.Error("expected err (salt = nil)")
	}
}

func TestVerifyNil(t *testing.T) {
	ctx := NewContext()
	password := make([]byte, 16)
	salt := make([]byte, 16)
	hash := make([]byte, 32)

	_, err := ctx.Verify(nil, password, salt)
	if err == nil {
		t.Error("expected err (hash = nil)")
	}

	_, err = ctx.Verify(hash, nil, salt)
	if err == nil {
		t.Error("expected err (password = nil)")
	}

	_, err = ctx.Verify(hash, password, nil)
	if err == nil {
		t.Error("expected err (salt = nil)")
	}
}

func TestVerify(t *testing.T) {
	testVerify(t, ModeArgon2d)
	testVerify(t, ModeArgon2i)
}

func testVerify(t *testing.T, mode Mode) {
	ctx := NewContext()
	ctx.Mode = mode
	password := []byte("hunter2")
	salt := []byte("somesalt")
	hash, err := ctx.Hash(password, salt)
	if err != nil {
		t.Fatal(err)
	}

	// Test correct password
	ok, err := ctx.Verify(hash, password, salt)
	if err != nil {
		t.Error(err)
	}
	if !ok {
		t.Errorf("Verify returned false with correct values (%s)", mode)
	}

	// Test incorrect password
	ok, err = ctx.Verify(hash, []byte("hunter3"), salt)
	if err != nil {
		t.Error(err)
	}
	if ok {
		t.Error("Verify returned true with incorrect password")
	}

	// Test incorrect salt
	ok, err = ctx.Verify(hash, password, []byte("somepepper"))
	if err != nil {
		t.Error(err)
	}
	if ok {
		t.Error("Verify returned true with incorrect salt")
	}
}
