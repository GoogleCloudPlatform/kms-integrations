// buildsigner is a simple CLI tool that performs a signature over standard
// input and writes it to standard output.
package main

import (
	"context"
	"flag"
	"io"
	"log"
	"os"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/sethvargo/go-gcpkms/pkg/gcpkms"
)

func signStdinToStdout(ctx context.Context, ckvName string) error {
	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return err
	}

	signer, err := gcpkms.NewSigner(ctx, kmsClient, ckvName)
	if err != nil {
		return err
	}

	hasher := signer.DigestAlgorithm().New()
	if _, err := io.Copy(hasher, os.Stdin); err != nil {
		return err
	}
	digest := hasher.Sum(nil)

	sig, err := signer.Sign(nil, digest, nil)
	if err != nil {
		return err
	}
	os.Stdout.Write(sig)
	return nil
}

func main() {
	signingCkv := flag.String("signing_key", "",
		"The full name of a KMS CryptoKeyVersion to sign with.")
	flag.Parse()

	if *signingCkv == "" {
		log.Fatal("flag -signing_key is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := signStdinToStdout(ctx, *signingCkv); err != nil {
		log.Fatal(err)
	}
}
