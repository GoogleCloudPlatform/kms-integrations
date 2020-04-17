package kmsp11

import (
	"fmt"
	"io"
	"text/scanner"
)

// p11Scanner is a specialization of scanner.Scanner with behaviors that
// are convenient for parsing FunctionDefs from pkcs11f.h.
type p11Scanner struct {
	inner scanner.Scanner
}

func newP11Scanner(r io.Reader) *p11Scanner {
	s := new(p11Scanner)
	s.inner.Init(r)
	s.inner.Error = func(_ *scanner.Scanner, msg string) {
		s.errorf(msg)
	}
	return s
}

// scanError satisfies the error interface.
type scanError string

func (e scanError) Error() string {
	return string(e)
}

// Report a scan error by panicking with the provided message.
func (s *p11Scanner) errorf(format string, a ...interface{}) {
	msg := fmt.Sprintf("at %v: %s", s.inner.Pos(), fmt.Sprintf(format, a...))
	panic(scanError(msg))
}

// Advance the scanner.
func (s *p11Scanner) Scan() rune {
	return s.inner.Scan()
}

// Retrieve the text of the current token.
func (s *p11Scanner) Text() string {
	return s.inner.TokenText()
}

// Advance the scanner. Panic if the encountered token does not match the
// provided rune or token type.
func (s *p11Scanner) MustScan(r rune) string {
	if t := s.Scan(); t != r {
		s.errorf("s.Scan()=%s, want %s", scanner.TokenString(t), scanner.TokenString(r))
	}
	return s.Text()
}

// Panic if the text at the current position does not match the provided text.
func (s *p11Scanner) TextMustBe(text string) {
	if s.Text() != text {
		s.errorf("s.Text()=%s, want %s", s.Text(), text)
	}
}

// Advance the scanner. Panic if the encountered token is not an identifier,
// or if its text does not match the provided text.
func (s *p11Scanner) MustScanIdent(text string) {
	s.MustScan(scanner.Ident)
	s.TextMustBe(text)
}

// Build up the function list by iterating over source blocks. Panic if the
// source blocks do not match the expected pattern.
//
// The expected pattern looks like:
//
// /* C_GetSlotList obtains a list of slots in the system. */
// CK_PKCS11_FUNCTION_INFO(C_GetSlotList)
// #ifdef CK_NEED_ARG_LIST
// (
//   CK_BBOOL       tokenPresent,  /* only slots with tokens */
//   CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
//   CK_ULONG_PTR   pulCount       /* receives number of slots */
// );
// #endif
func parseInternal(reader io.Reader) *CkFuncList {
	var funcs []*CkFunc
	s := newP11Scanner(reader)

	for s.Scan() != scanner.EOF {
		s.TextMustBe("CK_PKCS11_FUNCTION_INFO")
		s.MustScan('(')
		funcName := s.MustScan(scanner.Ident)
		s.MustScan(')')
		s.MustScan('#')
		s.MustScanIdent("ifdef")
		s.MustScanIdent("CK_NEED_ARG_LIST")
		s.MustScan('(')

		var args []*CkArg
		for {
			argType := s.MustScan(scanner.Ident)
			argName := s.MustScan(scanner.Ident)
			args = append(args, &CkArg{Datatype: argType, Name: argName})

			if t := s.Scan(); t == ')' {
				break // we reached the end of the arg list
			}
			s.TextMustBe(",") // there are more args
		}

		s.MustScan(';')
		s.MustScan('#')
		s.MustScanIdent("endif")

		funcs = append(funcs, &CkFunc{Name: funcName, Args: args})
	}

	return &CkFuncList{Functions: funcs}
}

// ParseFunctions builds up the function list by iterating over a
// series of source blocks that declare PKCS #11 functions.
func ParseFunctions(reader io.Reader) (f *CkFuncList, err error) {
	defer func() {
		// Based on example at https://golang.org/doc/effective_go.html#recover
		if e := recover(); e != nil {
			f = nil             // clear return value
			err = e.(scanError) // will re-panic if not our error
		}
	}()
	return parseInternal(reader), nil
}
