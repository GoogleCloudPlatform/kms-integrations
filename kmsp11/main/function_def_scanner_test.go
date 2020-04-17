package kmsp11

import (
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"
)

const getInfoSrc = `
/* C_GetInfo returns general information about Cryptoki. */
CK_PKCS11_FUNCTION_INFO(C_GetInfo)
#ifdef CK_NEED_ARG_LIST
(
  CK_INFO_PTR   pInfo  /* location that receives information */
);
#endif`

const getInfoDef = `
functions {
	name: "C_GetInfo"
	args {
		datatype: "CK_INFO_PTR"
		name: "pInfo"
	}
}`

func TestParseGetInfo(t *testing.T) {
	want := new(CkFuncList)
	if err := proto.UnmarshalText(getInfoDef, want); err != nil {
		t.Fatal(err)
	}

	got, err := ParseFunctions(strings.NewReader(getInfoSrc))
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ParseFunctions() mismatch (-want +got):\n%s", diff)
	}
}

const decryptInitSrc = `
/* C_DecryptInit initializes a decryption operation. */
CK_PKCS11_FUNCTION_INFO(C_DecryptInit)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
);
#endif`

const decryptInitDef = `
functions {
	name: "C_DecryptInit"
	args {
		datatype: "CK_SESSION_HANDLE"
		name: "hSession"
	}
	args {
		datatype: "CK_MECHANISM_PTR"
		name: "pMechanism"
	}
	args {
		datatype: "CK_OBJECT_HANDLE"
		name: "hKey"
	}
}`

func TestParseDecryptInit(t *testing.T) {
	want := new(CkFuncList)
	if err := proto.UnmarshalText(decryptInitDef, want); err != nil {
		t.Fatal(err)
	}

	got, err := ParseFunctions(strings.NewReader(decryptInitSrc))
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ParseFunctions() mismatch (-want +got):\n%s", diff)
	}
}

func TestParseInfoAndDecryptInit(t *testing.T) {
	want := new(CkFuncList)
	if err := proto.UnmarshalText(getInfoDef+decryptInitDef, want); err != nil {
		t.Fatal(err)
	}

	got, err := ParseFunctions(strings.NewReader(getInfoSrc + decryptInitSrc))
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ParseFunctions() mismatch (-want +got):\n%s", diff)
	}
}

func TestParseMalformed(t *testing.T) {
	if _, err := ParseFunctions(strings.NewReader("this must fail")); err == nil {
		t.Error("got err == nil; want not nil")
	}
}
