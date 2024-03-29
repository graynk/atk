# ATP - Aegis to KeePass

A simple tool to convert exported (and encrypted) JSON from [Aegis](https://getaegis.app/) to [KeePass](https://keepass.info/download.html) database. Notes, custom icons and Steam entries get exported as well.

## Installation
`go install github.com/graynk/atk@latest` or grab a binary from [Releases](https://github.com/graynk/atk/releases) page

## Usage
`atk /path/to/aegis-export.json /path/to/output.kdbx`

You will be asked to enter the password that was used to encrypt the Aegis vault. The same password will be used for resulting KDBX database.

## Limitations
* This tool does not support _changing_ existing databases, `atk` creates a separate clean database for your TOTP codes. You should not store TOTP secrets in the same database as your passwords anyway, since this removes all the benifits of having a second factor in the first place.
* This tool also does not accept unencrypted Aegis JSON files (yet, at least) as input
