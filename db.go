package main

import (
	"fmt"
	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"
	"maps"
	"os"
)

type db struct {
	Version int
	Entries []entry
	Groups  []group
}

type entry struct {
	Type     string
	UUID     string `json:"uuid"`
	Name     string
	Issuer   string
	Note     string
	Favorite bool
	Icon     string
	IconMime string `json:"icon_mime"`
	Info     dbInfo
	Groups   []string
}

type dbInfo struct {
	Secret string
	Algo   string
	Digits int
	Period int
}

type group struct {
	UUID string `json:"uuid"`
	Name string
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
	convertedEntry.AutoType.Enabled = wrappers.BoolWrapper{Bool: true}
	convertedEntry.AutoType.DefaultSequence = "{TOTP}"

	return convertedEntry, nil
}

func (d db) ToKeePass(path string, password []byte) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file for KeePass database: %v", err)
	}
	defer file.Close()

	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion4())
	db.Content.Meta.DatabaseName = "TOTP" // TODO provide optional argument for database name
	db.Credentials = gokeepasslib.NewPasswordCredentials(string(password))

	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "Default"
	groups := make(map[string]*gokeepasslib.Group)
	for _, group := range d.Groups {
		keepassGroup := gokeepasslib.NewGroup()
		keepassGroup.Name = group.Name
		groups[group.UUID] = &keepassGroup
	}

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
		if len(entry.Groups) == 0 {
			rootGroup.Entries = append(rootGroup.Entries, converted)
			continue
		}
		for _, groupUUID := range entry.Groups {
			keepassGroup, ok := groups[groupUUID]
			if !ok {
				fmt.Printf("Entry \"%s\" is listed as part of a group %s, but no such group was found\n", entry.Name, groupUUID)
				continue
			}
			keepassGroup.Entries = append(keepassGroup.Entries, converted)
		}
	}
	for groupPointer := range maps.Values(groups) {
		rootGroup.Groups = append(rootGroup.Groups, *groupPointer)
	}
	db.Content.Root.Groups = []gokeepasslib.Group{rootGroup}

	err = db.LockProtectedEntries()
	if err != nil {
		return fmt.Errorf("failed to lock entries when saving KeePass database: %v", err)
	}

	keepassEncoder := gokeepasslib.NewEncoder(file)
	err = keepassEncoder.Encode(db)
	if err != nil {
		return fmt.Errorf("failed to save KeePass database: %v", err)
	}

	return nil
}
