package main

import (
	"bufio"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/sha3"
)

func generateKeys(password []byte, difficulty int) (pubkey *[32]byte, privkey *[32]byte) {
	hasher := sha3.NewShake256()
	hasher.Write([]byte(password))

	trashBytes := make([]byte, 1024)
	for i := 0; i < 2<<difficulty; i++ {
		hasher.Read(trashBytes)
	}

	pubkey, privkey, err := box.GenerateKey(hasher)

	if err != nil {
		fmt.Println(err)
	}

	return pubkey, privkey
}

func main() {

	difficultyFlag := flag.Int("difficulty", 10, "difficulty of the key generation")
	keyfile := flag.String("keyfile", "keyfile", "file to store the key")
	inputfile := flag.String("input", "inputfile", "file to read in")
	outputfile := flag.String("output", "outputfile", "file to output to")
	generateKey := flag.Bool("generate", false, "generate a key")
	benchmark := flag.Bool("benchmark", false, "report the time it takes to derive a key for each difficulty level")

	flag.Parse()

	// print the time it takes to derive a key for each difficulty level
	if *benchmark {
		for i := 0; i < 31; i++ {
			start := time.Now()
			_, _ = generateKeys([]byte(""), i)
			elapsed := time.Since(start)
			fmt.Printf("difficulty: %d, time: %s\n", i, elapsed)
		}
		os.Exit(0)
	}

	// generate key
	if *generateKey && *keyfile != "keyfile" {
		fmt.Println("Enter password:")
		reader := bufio.NewReader(os.Stdin)
		text, err := reader.ReadString('\n')

		if err != nil {
			fmt.Println(err)
		}

		pubkey, _ := generateKeys([]byte(text), *difficultyFlag)
		os.WriteFile(*keyfile, pubkey[:], 0644)
		os.Exit(0)
	}

	// encrypt
	if !*generateKey && *keyfile != "keyfile" && *inputfile != "inputfile" && *outputfile != "outputfile" {
		key, err := os.ReadFile(*keyfile)
		if err != nil {
			fmt.Println(err)
		}
		pubkey := new([32]byte)
		copy(pubkey[:], key)

		input, err := os.ReadFile(*inputfile)
		if err != nil {
			fmt.Println(err)
		}

		encrypted, err := box.SealAnonymous(nil, []byte(input), pubkey, rand.Reader)
		if err != nil {
			fmt.Println(err)
		}
		os.WriteFile(*outputfile, encrypted, 0644)
		os.Exit(0)
	}

	if !*generateKey && *keyfile == "keyfile" && *inputfile != "inputfile" && *outputfile != "outputfile" {
		fmt.Println("Enter password:")
		reader := bufio.NewReader(os.Stdin)
		text, err := reader.ReadString('\n')

		if err != nil {
			fmt.Println(err)
		}

		pubkey, privkey := generateKeys([]byte(text), *difficultyFlag)

		encrypted, err := os.ReadFile(*inputfile)
		if err != nil {
			fmt.Println(err)
		}
		result, ok := box.OpenAnonymous(nil, encrypted, pubkey, privkey)
		if !ok {
			panic("decryption error")
		}
		os.WriteFile(*outputfile, result, 0644)
		os.Exit(0)
	}

	flag.PrintDefaults()

}
