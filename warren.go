package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/sha3"
)

const BUFFER_SIZE = 1024
const IV_SIZE = 16
const KEY_SIZE = 32
const SECRET_SIZE = 112
const HMAC_SIZE = 32

func fatalErr(err error) {
	if err != nil {
		panic(err)
	}
}

func generateKeys(password []byte) (pubkey *[KEY_SIZE]byte, privkey *[KEY_SIZE]byte) {
	// Argon2id to defend against brute force.
	seedBytes := argon2.IDKey(password, nil, 1, 64*1024, 4, KEY_SIZE)

	// SHA3 to provide a stream of bytes for key generation.
	hasher := sha3.NewShake256()
	hasher.Write(seedBytes)

	// NaCL to generate the key pair.
	pubkey, privkey, err := box.GenerateKey(hasher)
	fatalErr(err)

	return pubkey, privkey
}

func main() {

	keyfile := flag.String("keyfile", "keyfile", "file to store/read the public key. Requires -generate or -decrypt.")
	ciphertext := flag.String("decrypt", "ciphertext", "File to decrypt.")
	plaintext := flag.String("plaintext", "plaintext", "Where to write the plaintext.")
	generateKey := flag.Bool("generate", false, "generate a public key. Requires -keyfile")

	flag.Parse()

	// generate key
	if *generateKey && *keyfile != "keyfile" {
		fmt.Println("Enter password:")
		reader := bufio.NewReader(os.Stdin)
		text, err := reader.ReadString('\n')
		fatalErr(err)

		pubkey, _ := generateKeys([]byte(text))
		os.WriteFile(*keyfile, pubkey[:], 0644)
		os.Exit(0)
	}

	// encrypt
	if !*generateKey && *keyfile != "keyfile" && *ciphertext == "ciphertext" {
		key, err := os.ReadFile(*keyfile)
		fatalErr(err)

		pubkey := new([KEY_SIZE]byte)
		copy(pubkey[:], key)

		// aes key
		aesKey := make([]byte, KEY_SIZE)
		_, err = rand.Read(aesKey)
		fatalErr(err)
		// hmac key
		hmacKey := make([]byte, KEY_SIZE)
		_, err = rand.Read(hmacKey)
		fatalErr(err)

		// append the secrets to be encrypted, and encrypt them
		secrets := append(aesKey, hmacKey...)
		encrypted, err := box.SealAnonymous(nil, []byte(secrets), pubkey, rand.Reader)
		fatalErr(err)

		fmt.Print(string(encrypted))

		// prep the cipher. AES CTR with SHA256 HMAC. Zero IV because the key is guaranteed unique.
		iv := [IV_SIZE]byte{}

		block, err := aes.NewCipher(aesKey)
		fatalErr(err)

		ctr := cipher.NewCTR(block, iv[:])
		mac := hmac.New(sha256.New, hmacKey)

		// loop over stdin, reading bytes into plaintext and writing encrypted bytes to stdout, MACing over the ciphertext.
		plaintextBytes := make([]byte, BUFFER_SIZE)
		ciphertextBytes := make([]byte, BUFFER_SIZE)
		reader := bufio.NewReaderSize(os.Stdin, BUFFER_SIZE)
		for {

			num, err := reader.Read(plaintextBytes)
			if num == 0 {
				break
			}
			fatalErr(err)

			ctr.XORKeyStream(ciphertextBytes[:num], plaintextBytes[:num])
			mac.Write(ciphertextBytes[:num])
			fmt.Print(string(ciphertextBytes[:num]))
		}

		// write the HMAC
		fmt.Print(string(mac.Sum(nil)))

		os.Exit(0)
	}

	// decrypt
	if !*generateKey && *keyfile == "keyfile" && *ciphertext != "ciphertext" && *plaintext != "plaintext" {
		fmt.Println("Enter password:")
		reader := bufio.NewReader(os.Stdin)
		text, err := reader.ReadString('\n')
		fatalErr(err)

		// Recreate the keys from the password.
		pubkey, privkey := generateKeys([]byte(text))

		encrypted, err := os.ReadFile(*ciphertext)
		fatalErr(err)

		// Unbox the randomly generated secrets.
		result, ok := box.OpenAnonymous(nil, encrypted[:SECRET_SIZE], pubkey, privkey)
		if !ok {
			panic("decryption error")
		}

		// Prep the secrets for decryption.
		aesKey := result[:KEY_SIZE]
		hmacKey := result[KEY_SIZE:]
		iv := [IV_SIZE]byte{}

		// The payload is the data after the random secrets but before the hmac.
		payload := encrypted[SECRET_SIZE : len(encrypted)-HMAC_SIZE]
		// The hmac is whatever's left.
		hmacResult := encrypted[len(encrypted)-HMAC_SIZE:]

		// Pass one. Verify the HMAC.
		mac := hmac.New(sha256.New, hmacKey)
		mac.Write(payload)
		if !hmac.Equal(hmacResult, mac.Sum(nil)) {
			panic("HMAC verification failed")
		}

		plaintextBytes := make([]byte, len(payload))

		// Pass two. Decrypt the payload.
		block, err := aes.NewCipher(aesKey)
		fatalErr(err)

		ctr := cipher.NewCTR(block, iv[:])
		ctr.XORKeyStream(plaintextBytes, payload)

		os.WriteFile(*plaintext, plaintextBytes, 0644)
		os.Exit(0)
	}

	flag.PrintDefaults()
	os.Stderr.WriteString("Typical usage: \n\n")
	os.Stderr.WriteString("./warren.exe -keyfile key -generate\n")
	os.Stderr.WriteString("./warren.exe -keyfile key < test | tee > encrypted\n")
	os.Stderr.WriteString("./warren.exe -decrypt encrypted -plaintext result\n")
}
