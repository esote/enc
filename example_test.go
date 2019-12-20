package enc_test

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/esote/enc"
)

func Example() {
	// When placed in main, this program:
	//
	// 1. Take an input file and an output filename.
	//
	// 2. The contents of the input file are encrypted and written to the
	// output filename. A hash of the output file is written to standard
	// output.
	//
	// 3. The data is then decrypted again and printed to standard output.

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

	data, hash, err := enc.Encrypt(pass, &in)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(hex.EncodeToString(hash))

	if err = ioutil.WriteFile(os.Args[2], data, 0600); err != nil {
		log.Fatal(err)
	}

	var out []byte
	if err = enc.Decrypt(data, pass, &out); err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(out))
}
