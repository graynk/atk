# ATP - Aegis to KeePass

A simple tool to convert exported (and encrypted) Aegis database to standalone KeePass

## Installation
`go install github.com/graynk/atk@latest` or grab a binary from [Releases](https://github.com/graynk/atk/releases) page

## Usage
`atk /path/to/aegis-export.json /path/to/output.kdbx`

You will be asked to input the password that was used to encrypt the Aegis vault. The same password will be used for resulting KDBX database. 
