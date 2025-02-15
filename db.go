package main

import (
	"fmt"
	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"
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
		return convertedEntry, fmt.Errorf("unknown type for entry \"%s\": %s", e.Name, e.Type)
	}

	values := []gokeepasslib.ValueData{
		{
			Key: "Title",
			Value: gokeepasslib.V{
				Content: e.Issuer,
			},
		},
		{
			Key: "UserName",
			Value: gokeepasslib.V{
				Content: e.Name,
			},
		},
		{
			Key: "Notes",
			Value: gokeepasslib.V{
				Content: e.Note,
			},
		},
		{
			Key: "TOTP Settings",
			Value: gokeepasslib.V{
				Content:   totpFormat,
				Protected: wrappers.BoolWrapper{Bool: true},
			},
		},
		{
			Key: "TOTP Seed",
			Value: gokeepasslib.V{
				Content:   e.Info.Secret,
				Protected: wrappers.BoolWrapper{Bool: true},
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

	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion4())
	db.Content.Meta.DatabaseName = "TOTP" // TODO provide optional argument for database name
	db.Credentials = gokeepasslib.NewPasswordCredentials(string(password))
	entries := make([]gokeepasslib.Entry, 0, len(d.Entries))
	for _, entry := range d.Entries {
		converted, err := entry.ToKeePassEntry()
		if err != nil {
			fmt.Println(err)
			continue
		}
		if entry.Icon != "" {
			iconUUID := gokeepasslib.NewUUID()
			db.Content.Meta.CustomIcons = append(db.Content.Meta.CustomIcons, gokeepasslib.CustomIcon{
				UUID: iconUUID,
				Data: entry.Icon,
			})
			converted.CustomIconUUID = iconUUID
		}
		entries = append(entries, converted)
	}
	db.Content.Root.Groups = []gokeepasslib.Group{{Name: "Default", Entries: entries}}

	err = db.LockProtectedEntries()
	if err != nil {
		errAndExit("Failed to lock entries when saving KeePass database: %v", err)
	}

	keepassEncoder := gokeepasslib.NewEncoder(file)
	err = keepassEncoder.Encode(db)
	if err != nil {
		errAndExit("Failed to save KeePass database: %v", err)
	}
}
