// Package main reads the PKCS#11 function prototypes a CkFuncList textproto
// and adds them as context while executing the provided text template.
package main

import (
	"flag"
	"io/ioutil"
	"kmsp11"
	"log"
	"os"
	"text/template"

	"github.com/golang/protobuf/proto"
)

var (
	funcListPath = flag.String("func_list_path", "", "path to function list proto")
	templatePath = flag.String("template_path", "", "path to template file")
)

func mustReadFile(filePath string) string {
	f, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatalf("error reading file at %s: %+v", filePath, err)
	}
	return string(f)
}

func main() {
	flag.Parse()

	funcs := new(kmsp11.CkFuncList)
	if err := proto.UnmarshalText(mustReadFile(*funcListPath), funcs); err != nil {
		log.Fatalf("error parsing function list textproto: %+v", err)
	}

	templateFile := mustReadFile(*templatePath)
	t, err := new(template.Template).Parse(string(templateFile))
	if err != nil {
		log.Fatalf("error parsing template: %+v", err)
	}

	if err := t.Execute(os.Stdout, funcs); err != nil {
		log.Fatalf("error executing template: %+v", err)
	}
}
