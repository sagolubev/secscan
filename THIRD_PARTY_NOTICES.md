# Third-Party Notices

## Opengrep

The `scanner/opengrep` image redistributes the unmodified Opengrep executable.

- Project: https://github.com/opengrep/opengrep
- Version: `v1.29.0`
- Source revision: `344509d693c852eaac4fc1eeffaf2f655c531b5a`
- License: GNU Lesser General Public License 2.1
- License text: `/licenses/OPENGREP-LGPL-2.1.txt` inside the image
- Source: https://github.com/opengrep/opengrep/tree/344509d693c852eaac4fc1eeffaf2f655c531b5a

Verified release assets:

- `opengrep_musllinux_x86`:
  `sha256:1b474bf207905a3cffe4e915fe36895835bc89de2620cb2ffd88ca512d9ea31b`
- `opengrep_musllinux_aarch64`:
  `sha256:6cccb7466a98608e308204e17b259f4ca3a9028c6eb71e6b07ea21b89026c484`

The rules under `scanner/opengrep/rules` are original secscan project files
licensed separately under the MIT License in that directory.
