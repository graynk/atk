package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

func errAndExit(message string, err error) {
	if err == nil {
		fmt.Println(message)
	} else {
		fmt.Printf(message, err)
	}
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		errAndExit("Please pass the path to the encrypted Aegis JSON file as parameter", nil)
	}
	if len(os.Args) < 3 {
		errAndExit("Please pass the path to the desired output file", nil)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		errAndExit("Failed to read exported file: %v", err)
	}
	exported := aegis{}
	err = json.Unmarshal(data, &exported)
	if err != nil {
		errAndExit("Improperly formatted JSON file: %v", err)
	}
	fmt.Println("Please input your master password")
	var reader = bufio.NewReader(os.Stdin)
	password, err := reader.ReadBytes('\n')
	if err != nil {
		errAndExit("Failed to read password from input: %v", err)
	}
	if len(password) < 2 {
		errAndExit("Empty password", nil)
	}
	password = password[:len(password)-1]
	aegisDb := exported.Decrypt(password)
	if len(aegisDb.Entries) == 0 {
		errAndExit("No entries in the database, nothing to save", nil)
	}
	aegisDb.ToKeePass(os.Args[2], password)
}
