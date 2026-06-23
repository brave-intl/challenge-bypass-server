package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
)

func main() {
	flag.Parse()

	for _, arg := range flag.Args() {
		f, err := os.Open(arg)
		if err != nil {
			panic("failed to open file: " + err.Error())
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() { // each line
			parts := strings.Split(scanner.Text(), ",")

			key := &crypto.SigningKey{}
			err := key.UnmarshalText([]byte(parts[1]))
			if err != nil {
				log.Printf("failed unmarshal key: %s", err.Error())
			}
			pubkey, err := key.PublicKey().MarshalText()
			if err != nil {
				log.Printf("failed marshal pubkey: %s", err.Error())
			}

			fmt.Println(parts[0] + "," + parts[1] + "," + string(pubkey))
		}
		if err := scanner.Err(); err != nil {
			panic("scanning failed: " + err.Error())
		}
	}
}
