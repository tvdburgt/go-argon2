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
				Version:        Version10,
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
				Mode:           ModeArgon2i,
				Version:        Version13,
			},
			bytes.Repeat([]byte{1}, 32),
			bytes.Repeat([]byte{2}, 16),
			"c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
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
				Version:        Version10,
			},
			bytes.Repeat([]byte{1}, 32),
			bytes.Repeat([]byte{2}, 16),
			"96a9d4e5a1734092c85e29f410a45914a5dd1f5cbf08b2670da68a0285abf32b",
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
				Version:        Version13,
			},
			bytes.Repeat([]byte{1}, 32),
			bytes.Repeat([]byte{2}, 16),
			"512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
		},
		{
			&Context{
				Iterations:     3,
				Memory:         1 << 5,
				Parallelism:    4,
				Secret:         bytes.Repeat([]byte{3}, 8),
				AssociatedData: bytes.Repeat([]byte{4}, 12),
				HashLen:        32,
				Mode:           ModeArgon2id,
				Version:        Version10,
			},
			bytes.Repeat([]byte{1}, 32),
			bytes.Repeat([]byte{2}, 16),
			"b64615f07789b66b645b67ee9ed3b377ae350b6bfcbb0fc95141ea8f322613c0",
		},
		{
			&Context{
				Iterations:     3,
				Memory:         1 << 5,
				Parallelism:    4,
				Secret:         bytes.Repeat([]byte{3}, 8),
				AssociatedData: bytes.Repeat([]byte{4}, 12),
				HashLen:        32,
				Mode:           ModeArgon2id,
				Version:        Version13,
			},
			bytes.Repeat([]byte{1}, 32),
			bytes.Repeat([]byte{2}, 16),
			"0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
		},
	}

	for i, v := range vectors {
		expected, _ := hex.DecodeString(v.hash)
		hash, err := Hash(v.ctx, v.password, v.salt)
		if err != nil {
			t.Errorf("received error: %s (%d)", err, i)
		}
		if !bytes.Equal(hash, expected) {
			t.Errorf("%d:      got: %x", i, hash)
			t.Errorf("%d: expected: %x", i, expected)
		}
	}

}

func TestHashEncoded(t *testing.T) {
	ctx := NewContext(ModeArgon2d)

	password = []byte("somepassword")
	salt := []byte("somesalt")

	expected := "$argon2d$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$THaZx86KeqT+xuygENqvxaYIk3zu4wH0UmqzBL/wrdQ"

	s, err := HashEncoded(ctx, password, salt)
	if err != nil {
		t.Fatal(err)
	}
	if s != expected {
		t.Fatalf("HashEncoded: got %q  want %q", s, expected)
	}

	ctx.Version = Version10
	expected = "$argon2d$v=16$m=4096,t=3,p=1$c29tZXNhbHQ$9zHzndOtdbtKI3zBlrpnnpjNj9FnrkeiK43kb8NuuMc"

	s, err = HashEncoded(ctx, password, salt)
	if err != nil {
		t.Fatal(err)
	}
	if s != expected {
		t.Fatalf("HashEncoded: got %q  want %q", s, expected)
	}
}

func TestHash_Error(t *testing.T) {
	ctx := NewContext()
	_, err := Hash(ctx, []byte("password"), []byte("s"))
	if err != ErrSaltTooShort {
		t.Errorf("got %q  want %q", err, ErrSaltTooShort)
	}

	ctx = NewContext()
	ctx.Mode = 99
	_, err = Hash(ctx, []byte("password"), []byte("somesalt"))
	if err != ErrIncorrectType {
		t.Errorf("got %q  want %q", err, ErrIncorrectType)
	}

	ctx = NewContext()
	ctx.Memory = 4
	_, err = Hash(ctx, []byte("password"), []byte("somesalt"))
	if err != ErrMemoryTooLittle {
		t.Errorf("got %q  want %q", err, ErrMemoryTooLittle)
	}
}

func TestVerify(t *testing.T) {
	ctx := NewContext(ModeArgon2d)
	testVerify(t, ctx)

	ctx.Mode = ModeArgon2i
	testVerify(t, ctx)
}

func TestVerifyEncoded(t *testing.T) {
	ctx := NewContext(ModeArgon2d)
	testVerifyEncoded(t, ctx)

	ctx.Mode = ModeArgon2i
	testVerifyEncoded(t, ctx)
}

func TestFlagClearPassword(t *testing.T) {
	ctx := NewContext()
	ctx.Flags = FlagDefault
	password := []byte("somepassword")
	salt := []byte("somesalt")

	Hash(ctx, password, salt)
	if !bytes.Equal([]byte("somepassword"), password) {
		t.Fatalf("password slice is modified")
	}

	ctx.Flags = FlagClearPassword
	Hash(ctx, password, salt)
	if !bytes.Equal(make([]byte, len(password)), password) {
		t.Fatalf("password slice is not cleared")
	}
}

func TestFlagClearSecret(t *testing.T) {
	ctx := NewContext()
	ctx.Flags = FlagDefault
	ctx.Secret = []byte("somesecret")
	password := []byte("somepassword")
	salt := []byte("somesalt")

	Hash(ctx, password, salt)
	if !bytes.Equal([]byte("somesecret"), ctx.Secret) {
		t.Fatalf("secret slice is modified")
	}

	ctx.Flags = FlagClearSecret
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
	ok, err := VerifyEncoded(s, pw)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Errorf("VerifyEncoded(s, []byte(%q)) = false  want true", pw)
	}

	pw = []byte("someotherpassword")
	ok, err = VerifyEncoded(s, pw)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Errorf("VerifyEncoded(s, []byte(%q)) = true  want false", pw)
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
		t.Fatal(err)
	}
	if !ok {
		t.Errorf("Verify(..) = false  want true (%v)", ctx)
	}

	// Test incorrect password
	ok, err = Verify(ctx, hash, []byte("hunter3"), salt)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Errorf("Verify(badpw) = true  want false (%v)", ctx)
	}

	// Test incorrect salt
	ok, err = Verify(ctx, hash, password, []byte("somepepper"))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Errorf("Verify(badsalt) = true  want false (%v)", ctx)
	}
}
