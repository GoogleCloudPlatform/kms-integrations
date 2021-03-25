package main

import (
	"crypto/aes"
	"crypto/cipher"
	"flag"
	"io/ioutil"
	"log"
	"os"
)

var (
	wrappedKeyFile  = flag.String("wrapped_key_file", "", "the path to a wrapped key file with IV prepended")
	wrappingKeyFile = flag.String("wrapping_key_file", "", "the path to a file that contains a wrapping key")
)

func unwrapKey(wrappingKeyFile, wrappedKeyFile string) ([]byte, error) {
	wrappingKey, err := ioutil.ReadFile(wrappingKeyFile)
	if err != nil {
		return nil, err
	}

	wrappedKey, err := ioutil.ReadFile(wrappedKeyFile)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, wrappedKey[:12], wrappedKey[12:], nil)
}

func main() {
	flag.Parse()

	if *wrappedKeyFile == "" {
		log.Fatal("--wrapped_key_file is required")
	}
	if *wrappingKeyFile == "" {
		log.Fatal("--wrapping_key_file is required")
	}

	b, err := unwrapKey(*wrappingKeyFile, *wrappedKeyFile)
	if err != nil {
		log.Fatal(err)
	}
	os.Stdout.Write(b)
}
