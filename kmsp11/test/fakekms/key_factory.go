package fakekms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"errors"
	"fmt"
)

//go:embed testdata/*.pem
var testdata embed.FS

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
	key, err := func() (*rsa.PrivateKey, error) {
		pemKey, err := testdata.ReadFile(fmt.Sprintf("testdata/rsa_%d_private.pem", f))
		if err != nil {
			return nil, fmt.Errorf("unsupported RSA key size: %d", f)
		}
		block, _ := pem.Decode(pemKey)
		if block == nil || block.Type != "RSA PRIVATE KEY" {
			return nil, errors.New("failed to decode PEM block containing RSA private key")
		}
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}()
	if err != nil {
		panic("error loading pregenerated RSA private key: " + err.Error())
	}
	return key
}

type symmetricKeyFactory int

func (f symmetricKeyFactory) Generate() interface{} {
	k := make([]byte, int(f)/8)
	if _, err := rand.Read(k); err != nil {
		panic(err) // we ran out of entropy
	}
	return k
}
