package argon2_test

import (
	"fmt"
	"github.com/tvdburgt/go-argon2"
	"log"
)

func ExampleHash() {
	password := []byte("password")
	salt := make([]byte, 16) // pad salt to 16 bytes
	copy(salt, []byte("somesalt"))

	ctx := &argon2.Context{
		Iterations:  2,
		Memory:      1 << 16,
		Parallelism: 4,
		HashLen:     32,
		Mode:        argon2.ModeArgon2i,
		Version:     argon2.Version10,
	}

	hash, err := argon2.Hash(ctx, password, salt)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%x\n", hash)

	// Output:
	// 4162f32384d8f4790bd994cb73c83a4a29f076165ec18af3cfdcf10a8d1b9066
}

func ExampleHashEncoded() {
	password := []byte("password")
	salt := make([]byte, 16) // pad salt to 16 bytes
	copy(salt, []byte("somesalt"))

	ctx := &argon2.Context{
		Iterations:  2,
		Memory:      1 << 16,
		Parallelism: 4,
		HashLen:     32,
		Mode:        argon2.ModeArgon2i,
		Version:     argon2.Version10,
	}

	s, err := argon2.HashEncoded(ctx, password, salt)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(s)

	// Output:
	// $argon2i$v=16$m=65536,t=2,p=4$c29tZXNhbHQAAAAAAAAAAA$QWLzI4TY9HkL2ZTLc8g6SinwdhZewYrzz9zxCo0bkGY
}
