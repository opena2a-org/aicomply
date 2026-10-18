# Commands

The CLI has one command, `scan`, which reads files or piped stdin; `npx @opena2a/aicomply scan --help` lists its options.

## Exit codes

Exit code is `0` for CLEAN and `1` when anything is flagged, so it drops straight into CI.
It is `2` on a usage error or no input (stdin is a terminal, or every input is 0 bytes,
as an empty `git diff` is). An input of 0 bytes beside others is not classified: it is
listed as `0 bytes, nothing to classify` (`--json`: `"bytes": 0`, `"verdict": null`,
`"layers": []`) and does not decide the exit code.
