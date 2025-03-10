package main

import (
	"fmt"
	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"
	"maps"
	"net/url"
	"os"
	"strconv"
)

type OtpStyle int

const (
	KeeTrayTotp OtpStyle = iota
	KeePass2
	KeeWebOtp
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
	Secret  string
	Algo    string
	Digits  int
	Period  int
	Counter int
}

type group struct {
	UUID string `json:"uuid"`
	Name string
}

func incompatibleFormatError(entry, format, style string) error {
	return fmt.Errorf("Entry \"%s\" uses %s format, which is not supported for %s-style OTPs", entry, format, style)
}

func (e entry) GetKeeTrayFormat() ([]gokeepasslib.ValueData, error) {
	var content string
	if e.Type == "totp" {
		content = fmt.Sprintf("%d;%d", e.Info.Period, e.Info.Digits)
	} else if e.Type == "steam" {
		content = fmt.Sprintf("%d;S", e.Info.Period)
	} else if e.Type == "hotp" {
		return nil, incompatibleFormatError(e.Name, "HOTP", "KeePassXC/KeeTray")
	} else {
		return nil, fmt.Errorf("Unknown type for entry \"%s\": %s", e.Name, e.Type)
	}
	return []gokeepasslib.ValueData{
		{
			Key: "TOTP Settings",
			Value: gokeepasslib.V{
				Content:   content,
				Protected: wrappers.BoolWrapper{Bool: true},
			},
		},
		{
			Key: "TOTP Seed",
			Value: gokeepasslib.V{
				Content:   e.Info.Secret,
				Protected: wrappers.BoolWrapper{Bool: true},
			},
		}}, nil

}

func (e entry) GetKeePass2TotpFormat() ([]gokeepasslib.ValueData, error) {
	var algo string
	switch e.Info.Algo {
	case "SHA1":
		algo = "HMAC-SHA-1"
	case "SHA256":
		algo = "HMAC-SHA-256"
	case "SHA512":
		algo = "HMAC-SHA-512"
	default:
		return nil, fmt.Errorf("Unknown algorithm for entry \"%s\": %s", e.Name, e.Info.Algo)
	}
	return []gokeepasslib.ValueData{
		{
			Key: "TimeOtp-Secret-Base32",
			Value: gokeepasslib.V{
				Content:   e.Info.Secret,
				Protected: wrappers.BoolWrapper{Bool: true},
			},
		},
		{
			Key: "TimeOtp-Period",
			Value: gokeepasslib.V{
				Content:   strconv.Itoa(e.Info.Period),
				Protected: wrappers.BoolWrapper{Bool: true},
			},
		},
		{
			Key: "TimeOtp-Length",
			Value: gokeepasslib.V{
				Content:   strconv.Itoa(e.Info.Digits),
				Protected: wrappers.BoolWrapper{Bool: true},
			},
		},
		{
			Key: "TimeOtp-Algorithm",
			Value: gokeepasslib.V{
				Content:   algo,
				Protected: wrappers.BoolWrapper{Bool: true},
			},
		},
	}, nil
}

func (e entry) GetKeePass2HotpFormat() ([]gokeepasslib.ValueData, error) {
	return []gokeepasslib.ValueData{
		{
			Key: "HmacOtp-Secret-Base32",
			Value: gokeepasslib.V{
				Content:   e.Info.Secret,
				Protected: wrappers.BoolWrapper{Bool: true},
			},
		},
		{
			Key: "HmacOtp-Counter",
			Value: gokeepasslib.V{
				Content:   strconv.Itoa(e.Info.Counter),
				Protected: wrappers.BoolWrapper{Bool: true},
			},
		},
	}, nil
}

func (e entry) GetKeeWebFormat() ([]gokeepasslib.ValueData, error) {
	issuer := url.QueryEscape(e.Issuer)
	label := url.QueryEscape(e.Name)
	var content string
	switch e.Type {
	case "steam":
		// https://github.com/keeweb/keeweb/issues/564#issuecomment-535221800
		// kinda annoying since other clients seem to expect otpauth://steam
		fmt.Printf("Setting \"otp\" value for \"%s\" entry to otpauth://totp, depending on your client you may need to change it manually to otpauth://steam\n", e.Name)
		content = fmt.Sprintf("otpauth://totp/%s:%s?issuer=%s&secret=%s", label, issuer, issuer, e.Info.Secret)
	case "totp":
		content = fmt.Sprintf("otpauth://%s/%s:%s?issuer=%s&secret=%s&algorithm=%s&digits=%d&period=%d", e.Type, label, issuer, issuer, e.Info.Secret, e.Info.Algo, e.Info.Digits, e.Info.Period)
	case "hotp":
		content = fmt.Sprintf("otpauth://%s/%s:%s?issuer=%s&secret=%s&counter=%d", e.Type, label, issuer, issuer, e.Info.Secret, e.Info.Counter)
	default:
		return nil, fmt.Errorf("Unknown algorithm for entry \"%s\": %s", e.Name, e.Info.Algo)
	}
	return []gokeepasslib.ValueData{{
		Key: "otp",
		Value: gokeepasslib.V{
			Content:   content,
			Protected: wrappers.BoolWrapper{Bool: true},
		},
	}}, nil
}

func (e entry) ToKeePassEntry(style OtpStyle) (gokeepasslib.Entry, error) {
	convertedEntry := gokeepasslib.NewEntry()

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
	}
	switch style {
	case KeeTrayTotp:
		convertedEntry.AutoType.DefaultSequence = "{TOTP}"
		keetrayValues, err := e.GetKeeTrayFormat()
		if err != nil {
			return convertedEntry, err
		}
		values = append(values, keetrayValues...)
	case KeePass2:
		var keepass2Values []gokeepasslib.ValueData
		var err error
		switch e.Type {
		case "totp":
			convertedEntry.AutoType.DefaultSequence = "{TIMEOTP}"
			keepass2Values, err = e.GetKeePass2TotpFormat()
		case "hotp":
			convertedEntry.AutoType.DefaultSequence = "{HMACOTP}"
			keepass2Values, err = e.GetKeePass2HotpFormat()
		case "steam":
			return convertedEntry, incompatibleFormatError(e.Name, "Steam", "KeePass2")
		default:
			return convertedEntry, fmt.Errorf("Unknown type for entry \"%s\": %s", e.Name, e.Type)
		}
		if err != nil {
			return convertedEntry, err
		}
		values = append(values, keepass2Values...)
	case KeeWebOtp:
		convertedEntry.AutoType.DefaultSequence = "{TOTP}"
		keeWebValues, err := e.GetKeeWebFormat()
		if err != nil {
			return convertedEntry, err
		}
		values = append(values, keeWebValues...)
	}
	convertedEntry.Values = values
	convertedEntry.AutoType.Enabled = wrappers.BoolWrapper{Bool: true}

	return convertedEntry, nil
}

func (d db) ToKeePass(path string, password []byte, style OtpStyle) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file for KeePass database: %v", err)
	}
	defer file.Close()

	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion4())
	db.Content.Meta.DatabaseName = "TOTP"
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
		converted, err := entry.ToKeePassEntry(style)
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
