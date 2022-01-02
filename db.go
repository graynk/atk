package main

import (
	"fmt"
	"github.com/tobischo/gokeepasslib"
	"log"
	"os"
)

type db struct {
	Version int
	Entries []entry
}

type entry struct {
	Type     string
	UUID     string
	Name     string
	Issuer   string
	Note     string
	Icon     string
	IconMime string `json:"icon_mime"`
	Info     dbInfo
}

type dbInfo struct {
	Secret string
	Algo   string
	Digits int
	Period int
}

func (e entry) ToKeePassEntry() (gokeepasslib.Entry, error) {
	convertedEntry := gokeepasslib.NewEntry()

	var totpFormat string

	switch e.Type {
	case "totp":
		totpFormat = fmt.Sprintf("%d;%d", e.Info.Period, e.Info.Digits)
	case "steam":
		totpFormat = fmt.Sprintf("%d;S", e.Info.Period)
	default:
		return convertedEntry, fmt.Errorf("unknown type: %s", e.Type)
	}

	values := []gokeepasslib.ValueData{
		{
			"Title",
			gokeepasslib.V{
				Content: e.Issuer,
			},
		},
		{
			"UserName",
			gokeepasslib.V{
				Content: e.Name,
			},
		},
		{
			"Notes",
			gokeepasslib.V{
				Content: e.Note,
			},
		},
		{
			"TOTP Settings",
			gokeepasslib.V{
				Content:   totpFormat,
				Protected: true,
			},
		},
		{
			"TOTP Seed",
			gokeepasslib.V{
				Content:   e.Info.Secret,
				Protected: true,
			},
		},
	}
	convertedEntry.Values = values

	return convertedEntry, nil
}

func (d db) ToKeePass(path string, password []byte) {
	file, err := os.Create(path)
	if err != nil {
		errAndExit("Failed to create file for KeePass database: %v", err)
	}
	defer file.Close()

	// create the new database
	db := gokeepasslib.NewDatabase()
	db.Content.Meta.DatabaseName = "KDBX4"
	db.Credentials = gokeepasslib.NewPasswordCredentials(string(password))
	entries := make([]gokeepasslib.Entry, 0, len(d.Entries))
	for _, entry := range d.Entries {
		converted, err := entry.ToKeePassEntry()
		if err != nil {
			log.Println(err)
			continue
		}
		entries = append(entries, converted)
	}
	db.Content.Root.Groups = []gokeepasslib.Group{{Name: "Default", Entries: entries}}

	// Lock entries using stream cipher
	err = db.LockProtectedEntries()
	if err != nil {
		errAndExit("Failed to lock entries when saving KeePass database: %v", err)
	}

	// and encode it into the file
	keepassEncoder := gokeepasslib.NewEncoder(file)
	err = keepassEncoder.Encode(db)
	if err != nil {
		errAndExit("Failed to save KeePass database: %v", err)
	}
}
