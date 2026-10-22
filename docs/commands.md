# Commands

The CLI has one command, `scan`, which reads files or piped stdin; `npx @opena2a/aicomply scan --help` lists its options.

## Exit codes

Exit code is `0` for CLEAN and `1` when anything is flagged, so it drops straight into CI.
It is `2` on a usage error or no input (stdin is a terminal, or every input is 0 bytes,
as an empty `git diff` is). An input of 0 bytes beside others is not classified and does
not decide the overall verdict or the exit code. The report and `--json` give it the same
verdict, `EMPTY`. The report lists it as
`EMPTY      empty.txt   0 bytes, nothing to classify`, and `--json` as
`"bytes": 0`, `"verdict": "EMPTY"`, `"layers": []`.

## An input that cannot be read

Each named file is read before any input is scanned, and one that cannot be read
ends the run: the CLI prints why on stderr, prints nothing on stdout, with `--json`
too, and exits `2`. This holds for a path that does not exist, for a directory, for
a file without read permission and for a file too large to scan as one input. Here
`card.txt` holds a card number and is not reported:

```
$ aicomply scan clean.txt /nonexistent.txt card.txt --json
aicomply: cannot read '/nonexistent.txt' (check the path). Try 'aicomply --help'.
```

A file of 2 GiB or more gets
`cannot read '<file>': it is 2 GiB or larger, and this CLI reads files under 2 GiB`.
A smaller file whose text does not decode into one string gets
`cannot scan '<file>': at <n> bytes it is too large to decode as one input`; on
Node 26.12 that was a file of 629145600 bytes decoded as UTF-8 and a UTF-16 file
of 300000000 bytes.

When stdin is scanned, it is read after the named files, and UTF-8 or UTF-16
stdin whose text does not decode into one string ends the run the same way, with
`cannot scan (stdin): at <n> bytes it is too large to decode as one input`; on
Node 26.12 that was 629145600 bytes decoded as UTF-8
(`head -c 629145600 /dev/zero | aicomply scan`) and UTF-16 input of 300000000 bytes.

A gate over the files of a diff can leave out the deleted ones:
`git diff --cached --name-only --diff-filter=d` lists the staged files without them.

## Output

The report lists the findings of an input in the order they appear in it, at most 50
of them. When an input has more, one line after them counts the rest by type, the most
frequent first:

```
    ... 49950 more (SSN 49950); use --json for all
```

`--json` lists every finding. `--quiet` prints only the verdict line. Given with
`--json`, it is not applied: the JSON report is printed, and stderr says
`aicomply: --json takes precedence over --quiet; drop --json to print only the verdict line`.

## stdin when files are named

When files are named and `-` is not among them, stdin is not scanned. If stdin is a
pipe or a socket, a line on stderr after the report says so:
`aicomply: stdin not read because files were named; add - to scan it too`. The CLI
tells a pipe from a terminal or a file without reading it, as a read would wait until
the writer closes the pipe, so the line follows a pipe that carries no bytes as well:
`true | aicomply scan clean.txt` prints it. With stdin from `/dev/null`
(`aicomply scan clean.txt < /dev/null`) it is not printed. A file with content on
stdin is a usage error (exit `2`) whose message names the form that scans it too,
`aicomply scan - <files>`.
