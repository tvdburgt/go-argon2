package argon2_test

import (
	"fmt"
	"github.com/tvdburgt/go-argon2"
	"log"
)

func ExampleHash() {
	hash, err := argon2.Hash(argon2.NewContext(), []byte("hunter2"), []byte("somesalt"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%x\n", hash)

	// Output:
	// bfedbc29c9aeb504765c48ec8e7a63f1cdd89f2830e3ab2f26d68a45263ffcae
}

func Example() {
	password := []byte("password")
	salt := make([]byte, 16) // pad salt to 16 bytes
	copy(salt, []byte("somesalt"))

	ctx := &argon2.Context{
		Iterations:  2,
		Memory:      1 << 16,
		Parallelism: 4,
		HashLen:     32,
		Mode:        argon2.ModeArgon2i,
	}

	hash, err := argon2.Hash(ctx, password, salt)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%x\n", hash)

	// Output:
	// 4162f32384d8f4790bd994cb73c83a4a29f076165ec18af3cfdcf10a8d1b9066
}
