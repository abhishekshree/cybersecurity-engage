package main

import (
	"crypto/rand"
	"log"
	"testing"
)

func TestMain(m *testing.M) {
	priv, err := GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}

	pk := priv.PublicKey

	plainText := []byte("Hello World")
	cipherText, err := Encrypt(&pk, plainText)
	if err != nil {
		panic(err)
	}

	plainText2, err := Decrypt(priv, cipherText)
	if err != nil {
		panic(err)
	}

	if string(plainText) != string(plainText2) {
		panic("decryption failed")
	}

	// ADD
	ciphers := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		ciphers[i], err = Encrypt(&pk, []byte("Hello World"))
		if err != nil {
			panic(err)
		}
	}
	_, err = HommorphicAddition(&pk, ciphers[0], ciphers[1], ciphers[2])
	if err != nil {
		panic(err)
	}

	log.Println("Test passed")
}
