package fakekms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

type keyFactory interface {
	Generate() interface{}
	// TODO(bdhess): implement for import
	// Parse([]byte) (interface{}, error)
}

type ecKeyFactory struct {
	curve elliptic.Curve
}

func (f *ecKeyFactory) Generate() interface{} {
	k, err := ecdsa.GenerateKey(f.curve, rand.Reader)
	if err != nil {
		panic(err) // we ran out of entropy
	}
	return k
}

type rsaKeyFactory int

func (f rsaKeyFactory) Generate() interface{} {
	k, err := rsa.GenerateKey(rand.Reader, int(f))
	if err != nil {
		panic(err) // we ran out of entropy, or bit size is too small
	}
	return k
}

type symmetricKeyFactory int

func (f symmetricKeyFactory) Generate() interface{} {
	k := make([]byte, int(f)/8)
	if _, err := rand.Read(k); err != nil {
		panic(err) // we ran out of entropy
	}
	return k
}
