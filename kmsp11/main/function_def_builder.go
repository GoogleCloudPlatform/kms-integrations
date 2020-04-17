// Package main reads the PKCS#11 function prototypes from
// pkcs11f.h and outputs them as a CkFuncList textproto.
package main

import (
	"flag"
	"kmsp11"
	"log"
	"os"

	"github.com/golang/protobuf/proto"
)

var pkcs11fPath = flag.String("pkcs11f_path", "", "path to pkcs11f.h")

func main() {
	flag.Parse()

	pkcs11f, err := os.Open(*pkcs11fPath)
	if err != nil {
		log.Fatalf("error reading file at %s: %v", *pkcs11fPath, err)
	}

	funcs, err := kmsp11.ParseFunctions(pkcs11f)
	if err != nil {
		log.Fatalf("error parsing file at %s: %v", *pkcs11fPath, err)
	}

	if err := proto.MarshalText(os.Stdout, funcs); err != nil {
		log.Fatalf("error marshaling textproto: %v", err)
	}
}
