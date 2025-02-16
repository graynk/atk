package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/term"
	"os"
	"strings"
)

func errAndExit(message string, err error) {
	if err == nil {
		fmt.Println(message)
	} else {
		fmt.Printf(message, err)
	}
	os.Exit(1)
}

func parseArgs() (*os.File, string) {
	for _, arg := range os.Args {
		if arg == "-h" || strings.Contains(arg, "help") {
			fmt.Printf("A simple tool to convert exported (and encrypted) JSON from Aegis to KeePass database.\n\nUsage:\natk /path/to/aegis-export.json /path/to/output.kdbx\n")
			os.Exit(0)
		}
	}

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

	return file, os.Args[2]
}

func readRuneFromStdin(prompt string) rune {
	fmt.Println(prompt)
	var reader = bufio.NewReader(os.Stdin)
	r, _, err := reader.ReadRune()
	if err != nil {
		errAndExit("Failed to read confirmation from stdin: %v", err)
	}

	return r
}

func isOverwriteOk(kdbxPath string) bool {
	stat, err := os.Stat(kdbxPath)
	if stat != nil || os.IsExist(err) {
		r := readRuneFromStdin("A file already exists at the specified output path. Are sure you want to rewrite it completely? Y/N")
		if r != 'Y' && r != 'y' {
			return false
		}
	}
	return true
}

func readStyle() OtpStyle {
	r := readRuneFromStdin(`What OTP-style should we use?
1. KeePassXC/KeeTrayTotp (Most common, uses TOTP Seed/TOTP Settings fields)
2. KeePass 2 (TimeOtp-Secret-Base32/HmacOtp-Secret-Base32)
3. KeeWeb (single "otp" field in a format otpauth://type/label?secret=abcd)`)
	switch r {
	case '1':
		return KeeTrayTotp
	case '2':
		return KeePass2
	case '3':
		return KeeWebOtp
	default:
		fmt.Printf("%v is not a valid option, please input 1, 2 or 3", r)
		return readStyle()
	}
}

func main() {
	file, kdbxPath := parseArgs()
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(file)
	if err != nil {
		errAndExit("Failed to read exported file: %v", err)
	}
	data := buf.Bytes()
	exported := aegis{}
	err = json.Unmarshal(data, &exported)
	if err != nil {
		errAndExit("Improperly formatted JSON file: %v", err)
	}
	fmt.Println("Please input your master password")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		errAndExit("Failed to read password from input: %v", err)
	}
	if len(password) < 1 {
		errAndExit("Empty password", nil)
	}
	aegisDb, err := exported.Decrypt(password)
	if err != nil {
		errAndExit("Failed to decrypt Aegis database: %v", err)
	}
	if len(aegisDb.Entries) == 0 {
		errAndExit("No entries in the database, nothing to save", nil)
	}
	if !isOverwriteOk(kdbxPath) {
		os.Exit(0)
	}
	style := readStyle()
	err = aegisDb.ToKeePass(kdbxPath, password, style)
	if err != nil {
		errAndExit("Conversion process failed: %v", err)
	}
	fmt.Println("Done")
}
