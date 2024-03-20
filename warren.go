package main

// Copyright (c) 2024 TomatoCo
// Released under GPL 3.0

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
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/sha3"
)

const VERSION = "1.0.0"

const BUFFER_SIZE = 4096
const IV_SIZE = 16
const KEY_SIZE = 32
const SECRET_SIZE = 112
const HMAC_SIZE = 32

func fatalErr(err error) {
	if err != nil {
		panic(err)
	}
}

func generateKeys(password string) (pubkey *[KEY_SIZE]byte, privkey *[KEY_SIZE]byte) {

	// now trim the newline suffix. Once for Linux, again for Windows.
	password = strings.TrimSuffix(password, "\n")
	password = strings.TrimSuffix(password, "\r")

	// Argon2id to defend against brute force.
	seedBytes := argon2.IDKey([]byte(password), nil, 1, 64*1024, 4, KEY_SIZE)

	// SHA3 to provide a stream of bytes for key generation.
	hasher := sha3.NewShake256()
	hasher.Write(seedBytes)

	// NaCL to generate the key pair.
	pubkey, privkey, err := box.GenerateKey(hasher)
	fatalErr(err)

	return pubkey, privkey
}

func main() {

	keyfile := flag.String("keyfile", "", "File to store/read the public key. Requires -generate or -decrypt.")
	ciphertext := flag.String("decrypt", "", "File to decrypt.")
	plaintext := flag.String("plaintext", "", "Where to write the plaintext.")
	generateKey := flag.Bool("generate", false, "Generate a public key. Requires -keyfile")
	version := flag.Bool("version", false, "print version ("+VERSION+").")

	flag.Parse()

	if *version {
		fmt.Println(VERSION)
		os.Exit(0)
	}

	// generate key
	if *generateKey && *keyfile != "" {
		fmt.Println("Enter password:")
		reader := bufio.NewReader(os.Stdin)
		text, err := reader.ReadString('\n')
		fatalErr(err)

		pubkey, _ := generateKeys(text)
		err = os.WriteFile(*keyfile, pubkey[:], 0644)
		fatalErr(err)
		os.Exit(0)
	}

	// encrypt
	if !*generateKey && *keyfile != "" {
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
	if !*generateKey && *keyfile == "" && *ciphertext != "" && *plaintext != "" {
		fmt.Println("Enter password:")
		reader := bufio.NewReader(os.Stdin)
		text, err := reader.ReadString('\n')
		fatalErr(err)

		// Recreate the keys from the password.
		pubkey, privkey := generateKeys(text)

		encryptedFile, err := os.OpenFile(*ciphertext, os.O_RDONLY, 0644)
		fatalErr(err)

		fileStat, err := encryptedFile.Stat()
		fatalErr(err)

		fileSize := fileStat.Size()
		payloadSize := fileSize - SECRET_SIZE - HMAC_SIZE

		naclSecret := make([]byte, SECRET_SIZE)
		_, err = encryptedFile.Read(naclSecret)
		fatalErr(err)

		// Unbox the randomly generated secrets.
		result, ok := box.OpenAnonymous(nil, naclSecret, pubkey, privkey)
		if !ok {
			panic("Boxed MAC verification failed. Wrong password or corrupt file.")
		}

		// Prep the secrets for decryption.
		aesKey := result[:KEY_SIZE]
		hmacKey := result[KEY_SIZE:]
		iv := [IV_SIZE]byte{}

		plaintextBytes := make([]byte, BUFFER_SIZE)
		ciphertextBytes := make([]byte, BUFFER_SIZE)

		// Pass one. Verify the HMAC.
		mac := hmac.New(sha256.New, hmacKey)

		// The payload is the data after the random secrets but before the hmac.
		payloadRemaining := payloadSize
		for payloadRemaining > 0 {
			num, err := encryptedFile.Read(ciphertextBytes[:min(payloadRemaining, BUFFER_SIZE)])
			payloadRemaining -= int64(num)
			if num == 0 {
				break
			}
			fatalErr(err)
			mac.Write(ciphertextBytes[:num])
		}

		// The hmac is whatever's left.
		hmacResult := make([]byte, HMAC_SIZE)
		_, err = encryptedFile.Read(hmacResult)
		fatalErr(err)

		if !hmac.Equal(hmacResult, mac.Sum(nil)) {
			panic("Payload HMAC verification failed. Corrupted file.")
		}

		f, err := os.Create(*plaintext)
		fatalErr(err)
		defer f.Close()

		writer := bufio.NewWriterSize(f, BUFFER_SIZE)

		// Pass two. Decrypt the payload.

		// seek back to the start of the file, skip the NaCL secret from earlier.
		_, err = encryptedFile.Seek(SECRET_SIZE, 0)
		fatalErr(err)

		block, err := aes.NewCipher(aesKey)
		fatalErr(err)

		ctr := cipher.NewCTR(block, iv[:])

		payloadRemaining = payloadSize
		for payloadRemaining > 0 {
			num, err := encryptedFile.Read(ciphertextBytes[:min(payloadRemaining, BUFFER_SIZE)])
			payloadRemaining -= int64(num)
			if num == 0 {
				break
			}
			fatalErr(err)
			ctr.XORKeyStream(plaintextBytes[:num], ciphertextBytes[:num])
			writer.Write(plaintextBytes[:num])
		}
		f.Sync()
		writer.Flush()
		os.Exit(0)
	}

	flag.PrintDefaults()
	os.Stderr.WriteString("Typical usage: \n\n")
	os.Stderr.WriteString("./warren.exe -keyfile key -generate\n")
	os.Stderr.WriteString("./warren.exe -keyfile key < test | tee > encrypted\n")
	os.Stderr.WriteString("./warren.exe -decrypt encrypted -plaintext result\n")
}
