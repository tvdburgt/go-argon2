package argon2

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestHash(t *testing.T) {
	vectors := []struct {
		ctx      *Context
		password []byte
		salt     []byte
		hash     string
	}{

		{
			&Context{
				Iterations:     3,
				Memory:         1 << 5,
				Parallelism:    4,
				Secret:         bytes.Repeat([]byte{3}, 8),
				AssociatedData: bytes.Repeat([]byte{4}, 12),
				HashLen:        32,
				Mode:           ModeArgon2i,
			},
			bytes.Repeat([]byte{1}, 32),
			bytes.Repeat([]byte{2}, 16),
			"87aeedd6517ab830cd9765cd8231abb2e647a5dee08f7c05e02fcb763335d0fd",
		},
		{
			&Context{
				Iterations:     3,
				Memory:         1 << 5,
				Parallelism:    4,
				Secret:         bytes.Repeat([]byte{3}, 8),
				AssociatedData: bytes.Repeat([]byte{4}, 12),
				HashLen:        32,
				Mode:           ModeArgon2d,
			},
			bytes.Repeat([]byte{1}, 32),
			bytes.Repeat([]byte{2}, 16),
			"96a9d4e5a1734092c85e29f410a45914a5dd1f5cbf08b2670da68a0285abf32b",
		},
	}

	for i, v := range vectors {
		expected, _ := hex.DecodeString(v.hash)
		hash, err := Hash(v.ctx, v.password, v.salt)
		if err != nil {
			t.Errorf("received error: %s (%d)", i, err)
		}
		if !bytes.Equal(hash, expected) {
			t.Errorf("assertion failed (%d: %s)", i, v.hash)
		}
	}

}

func TestHashEncoded(t *testing.T) {
	ctx := NewContext()
	ctx.Mode = ModeArgon2d
	s, err := HashEncoded(ctx, []byte("somepassword"), []byte("somesalt"))
	if err != nil {
		t.Fatal(err)
	}

	expected := "$argon2d$m=4096,t=3,p=1$c29tZXNhbHQ$9zHzndOtdbtKI3zBlrpnnpjNj9FnrkeiK43kb8NuuMc"
	if s != expected {
		t.Fatalf("HashEncoded: got %q; want %q", s, expected)
	}
}

func TestVerify(t *testing.T) {
	ctx := NewContext()

	ctx.Mode = ModeArgon2d
	testVerify(t, ctx)
	testVerifyEncoded(t, ctx)

	ctx.Mode = ModeArgon2i
	testVerify(t, ctx)
	testVerifyEncoded(t, ctx)
}

func TestFlagClearPassword(t *testing.T) {
	ctx := NewContext()
	ctx.Flags = FlagClearMemory
	password := []byte("somepassword")
	salt := []byte("somesalt")

	Hash(ctx, password, salt)
	if !bytes.Equal([]byte("somepassword"), password) {
		t.Fatalf("password slice is modified")
	}

	ctx.Flags = FlagClearMemory | FlagClearPassword
	Hash(ctx, password, salt)
	if !bytes.Equal(make([]byte, len(password)), password) {
		t.Fatalf("password slice is not cleared")
	}
}

func TestFlagClearSecret(t *testing.T) {
	ctx := NewContext()
	ctx.Flags = FlagClearMemory
	ctx.Secret = []byte("somesecret")
	password := []byte("somepassword")
	salt := []byte("somesalt")

	Hash(ctx, password, salt)
	if !bytes.Equal([]byte("somesecret"), ctx.Secret) {
		t.Fatalf("secret slice is modified")
	}

	ctx.Flags = FlagClearMemory | FlagClearSecret
	Hash(ctx, password, salt)
	if !bytes.Equal(make([]byte, len(ctx.Secret)), ctx.Secret) {
		t.Fatalf("secret slice is not cleared")
	}
}

func testVerifyEncoded(t *testing.T, ctx *Context) {
	s, err := HashEncoded(ctx, []byte("somepassword"), []byte("somesalt"))
	if err != nil {
		t.Fatal(err)
	}

	pw := []byte("somepassword")
	ok, _ := VerifyEncoded(s, pw)
	if !ok {
		t.Fatalf("VerifyEncoded(s, []byte(%q)) = false; want true", pw)
	}

	pw = []byte("someotherpassword")
	ok, _ = VerifyEncoded(s, pw)
	if ok {
		t.Fatalf("VerifyEncoded(s, []byte(%q)) = true; want false", pw)
	}
}

func testVerify(t *testing.T, ctx *Context) {
	password := []byte("hunter2")
	salt := []byte("somesalt")
	hash, err := Hash(ctx, password, salt)
	if err != nil {
		t.Fatal(err)
	}

	// Test correct password
	ok, err := Verify(ctx, hash, password, salt)
	if err != nil {
		t.Error(err)
	}
	if !ok {
		t.Errorf("Verify(..) = false; want true (%v)", ctx)
	}

	// Test incorrect password
	ok, err = Verify(ctx, hash, []byte("hunter3"), salt)
	if err != nil {
		t.Error(err)
	}
	if ok {
		t.Errorf("Verify(badpw) = true; want false (%v)", ctx)
	}

	// Test incorrect salt
	ok, err = Verify(ctx, hash, password, []byte("somepepper"))
	if err != nil {
		t.Error(err)
	}
	if ok {
		t.Errorf("Verify(badsalt) = true; want false (%v)", ctx)
	}
}
