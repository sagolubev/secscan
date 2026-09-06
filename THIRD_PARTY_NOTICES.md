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
