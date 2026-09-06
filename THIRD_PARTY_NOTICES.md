# Third-party notices

## Go YAML v3.0.4

Secscan uses `go.yaml.in/yaml/v3` to validate CI input structure before Poutine
runs. Go's standard library has no YAML parser.

- Source: https://github.com/yaml/go-yaml/tree/v3.0.4
- Licenses: MIT for the ported libyaml files; Apache License 2.0 for the remaining files.
- Original notices: [LICENSE](LICENSES/go-yaml-LICENSE.txt), [NOTICE](LICENSES/go-yaml-NOTICE.txt).
- Full Apache license: [Apache-2.0](LICENSES/Apache-2.0.txt).

Scanner images are fetched separately from their pinned upstream references.
They are not incorporated into the secscan binary. Opengrep image notices remain
in `scanner/opengrep/assets/THIRD_PARTY_NOTICES.md`.

## Additional code scanners

Semgrep 1.176.0 and Bearer 2.1.1 are pulled by digest from their upstream
registries during `secscan update`. They are not embedded or redistributed.
The official Semgrep image references proprietary source; this project does
not represent the image as LGPL-only. Semgrep uses the project's eight MIT
rules embedded with Opengrep, without downloading a third-party rule registry.

Bearer runs only on native amd64 container servers. Its static rules v0.48.4
(source commit `30a6919acec715bf915ff4704d1b4ffeac998eab`) are downloaded into
the user's private cache, with their Elastic License 2.0 retained as
`LICENSE.txt`. The rules and their license are verified by SHA-256; the rules
are not incorporated into this repository or the secscan binary.

Cppcheck 2.21.1 is built locally from pinned source during update. Its embedded
recipe includes the matching GPL source archive, license, build recipe and
runtime license notices in the resulting image. See
[Cppcheck notices](scanner/cppcheck/THIRD_PARTY_NOTICES.md).

## Go TOML v2.2.4

Secscan uses `github.com/pelletier/go-toml/v2` to parse static Gradle version
catalogs. Go's standard library has no TOML parser.

- Source: https://github.com/pelletier/go-toml/tree/v2.2.4
- License: MIT, retained in [LICENSE](LICENSES/go-toml-LICENSE.txt).
