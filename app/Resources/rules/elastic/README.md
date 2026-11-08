# Elastic macOS malware rules

YARA rules for macOS (`MacOS_*`) and multi-platform (`Multi_*`) threats from
[elastic/protections-artifacts](https://github.com/elastic/protections-artifacts) (`yara/rules`),
copyright Elasticsearch B.V., licensed under the Elastic License 2.0 (see `LICENSE.txt`).

This copy ships with permwatch so scanning works offline. When "Malicious server check and extra signatures"
is on, permwatch downloads the current version of the same files once a day.
