package enc_test

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/esote/enc"
)

func Example() {
	// When placed in main, this program takes an input file and an output
	// filename. The contents of the input file are encrypted and written to
	// the output filename, using the password read from standard input.
	// The data is then decrypted again and printed to standard output.
	if len(os.Args) < 3 {
		log.Fatal("usage: ./enc in out")
	}

	fmt.Print("pass: ")
	pass, err := bufio.NewReader(os.Stdin).ReadBytes('\n')
	if err != nil {
		log.Fatal(err)
	}

	in, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	data, err := enc.Encrypt(pass, &in)
	if err != nil {
		log.Fatal(err)
	}

	if err = ioutil.WriteFile(os.Args[2], data, 0600); err != nil {
		log.Fatal(err)
	}

	var out []byte
	if err = enc.Decrypt(data, pass, &out); err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(out))
}
