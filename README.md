# rpgmtool
A Python 3 command-line tool for working with RPG Maker archives(RGSS Archives). Supports RPG Maker XP, VX, VX Ace, and MV formats.

## Features
- List contents of RGSS archives
- Extract files from archives
- Create new archives
- Support for encrypted RPG Maker MV files
- Configurable encryption keys
- Verbose debug output

To extract (or decrypt) files from an archive (`file.rgss3a`) to the current directory, use:
```bash
    rpgmtool.py -x file.rgss3a
```
To create an archive (`file.rgss3a`, RPG Maker VX Ace by default) from the contents of a directory (`Data/`), use:
```bash
    rgsstool.py -c -d Data file.rgss3a
```
For RPG Maker XP format, use the -1 flag:
```bash
    rgsstool.py -c -1 file.rgssad Data/ Graphics/
```
For RPG Maker MV games, specify the game directory to extract encrypted files:
```bash
    rgsstool.py --rpgmv game_directory/
```
Additional options:
- `-l, --list`: List files in archive (default mode)
- `-x, --extract`: Extract files from archive  
- `-c, --create`: Create new archive from files
- `-d DIR, --dir DIR`: Directory to extract to or add files from
- `-k KEY, --key KEY`: Encryption key in hexadecimal (default: deadcafe)
- `-v, --verbose`: Show detailed debug information
- `--exts`: Comma-separated list of encrypted file extensions for RPG Maker MV 
  (default: .rpgmvp,.rpgmvm,.rpgmvo,.png_,.m4a_,.ogg_)

Use `--help` for full usage details.
