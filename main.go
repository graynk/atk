package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/term"
	"os"
	"syscall"
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
	file, err := os.Open(os.Args[1])
	if err != nil {
		errAndExit("Failed to open exported file: %v", err)
	}
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(file)
	if err != nil {
		errAndExit("Failed to read exported file: %v", err)
	}
	data := buf.Bytes()
	exported := aegis{}
	err = json.Unmarshal(data, &exported)
	if err != nil {
		errAndExit("Improperly formatted JSON file: %v", err)
	}
	fmt.Print("Please input your master password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		errAndExit("Failed to read password from input: %v", err)
	}
	if len(password) < 1 {
		errAndExit("Empty password", nil)
	}
	aegisDb := exported.Decrypt(password)
	if len(aegisDb.Entries) == 0 {
		errAndExit("No entries in the database, nothing to save", nil)
	}
	kdbxPath := os.Args[2]
	stat, err := os.Stat(kdbxPath)
	if stat != nil || os.IsExist(err) {
		fmt.Println("A file already exists at the specified output path. Are sure you want to rewrite it completely? Y/N")
		var reader = bufio.NewReader(os.Stdin)
		r, _, err := reader.ReadRune()
		if err != nil {
			errAndExit("Failed to read confirmation from stdin: %v", err)
		}
		if r != 'Y' && r != 'y' {
			os.Exit(0)
		}
	}
	aegisDb.ToKeePass(kdbxPath, password)
}
