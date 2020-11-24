// Package main starts a new fakekms server that listens on an OS-supplied port.
//
// The program starts up and prints its listening address to standard output. It
// then runs until it receives SIGINT or SIGTERM.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"oss-tools/kmsp11/test/fakekms"
)

var delay = flag.Duration("delay", 0,
	"the amount of time each request should be delayed before being processed")

func main() {
	flag.Parse()

	sigs := make(chan os.Signal)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	srv, err := fakekms.NewServerWithOptions(&fakekms.ServerOptions{
		Delay: *delay,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer srv.Close()
	fmt.Println(srv.Addr)
	fmt.Fprintln(os.Stderr, "ready to serve requests")

	sig := <-sigs
	fmt.Fprintln(os.Stderr, "shutting down on signal:", sig)
}
