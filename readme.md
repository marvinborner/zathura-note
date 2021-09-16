# Notability .note support for zathura

This plugin adds support for the proprietary .note format of Notability. Because I had to reverse engineer the file format, you should expect errors and many missing features.

## Installation

1. Install cairo, libplist, libzip and zathura (including header files obviously, e.g. using `-dev` suffix)
2. `meson zathura-note`
3. `cd zathura-note; sudo ninja install`
4. Enjoy!
