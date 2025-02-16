# ATP - Aegis to KeePass

A simple tool to convert exported (and encrypted) JSON from [Aegis](https://getaegis.app/) to [KeePass](https://keepass.info/download.html) database. 
Notes, custom icons and Steam entries get exported as well.

Unfortunately, there is no single agreed-upon way to store OTPs, as different plugins/clients expect different fields to be present.

`atk` supports following implementations:
* [KeePassXC](https://keepassxc.org/)/[KeeTray](https://github.com/KeeTrayTOTP/KeeTrayTOTP)/[KeePassium](https://keepassium.com/)/[Keepass2Android](https://github.com/PhilippC/keepass2android) (seems to be most common scheme)
* [KeePass 2](https://keepass.info/help/base/placeholders.html#otp)
* [KeeWeb/Key URI](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)

If your client doesn't support any of those styles - feel free to [open an issue](https://github.com/graynk/atk/issues/new) (or better yet - submit a PR)

## Installation
`go install github.com/graynk/atk@latest` or grab a binary from the [Releases](https://github.com/graynk/atk/releases) page

## Usage
`atk /path/to/aegis-export.json /path/to/output.kdbx`

You will be asked to enter the password that was used to encrypt the Aegis vault. The same password will be used for the resulting KDBX database.

## Limitations
* This tool does not support _changing_ existing databases, `atk` creates a separate clean database for your TOTP codes. You should not store TOTP secrets in the same database as your passwords anyway, since this removes all the benefits of having a second factor in the first place.
* This tool also does not accept unencrypted Aegis JSON files as input
