# Commands

The CLI has one command, `scan`, which reads files or piped stdin; `npx @opena2a/aicomply scan --help` lists its options.

## Exit codes

Exit code is `0` when every input is `CLEAN`, `1` when any input is flagged (`VIOLATION`
or `DENY`), and `2` when the scan reached no verdict: on a usage error; on no input
(stdin is a terminal, or every input is 0 bytes, as an empty `git diff` is); on a named
file that cannot be read or decoded and none is flagged
([An input that cannot be read](#an-input-that-cannot-be-read));
on a scan that ends on an internal error; and when an input is `INCOMPLETE` (the scan
could not evaluate it in full) and none is flagged. A flagged input decides the exit
even beside an `INCOMPLETE` or unreadable one. A gate passes on `0` only: `2` means the
scan reached no verdict, not that it found nothing.

An input of 0 bytes beside others is not classified and does
not decide the overall verdict or the exit code. The report and `--json` give it the same
verdict, `EMPTY`. The report lists it as
`EMPTY      empty.txt   0 bytes, nothing to classify`, and `--json` as
`"bytes": 0`, `"verdict": "EMPTY"`, `"layers": []`.

An `INCOMPLETE` input is not `CLEAN`. The report names the patterns that were not
evaluated on it, and `--json` lists them as `"notEvaluated"` beside
`"verdict": "INCOMPLETE"`.

## An input that cannot be read

A named file that cannot be read does not end the run. The other inputs are scanned
and reported, and the file is listed in its place as `UNREADABLE` with the reason.
This holds for a path that does not exist, for a directory, for a file without read
permission and for a file too large to scan as one input:

```
$ aicomply scan clean.txt /nonexistent.txt card.txt

  CLEAN      clean.txt   no finding in the 8 pattern classes (aicomply --help lists them)

  UNREADABLE /nonexistent.txt   cannot read (check the path)

  VIOLATION  card.txt   1 finding
    SSN          •••                confidence 0.95  layer regex  line 1 col 5
...
Verdict: VIOLATION  ·  1 finding across 2 inputs; 1 input could not be read. Block, redact, or log before this content reaches an LLM.
```

`--json` gives the file `"verdict": "UNREADABLE"`, `"bytes": null`, `"layers": []`,
`"findings": []` and the reason as `"error"`. `--quiet` prints only the verdict, so
stderr names each file that could not be read and why, as in
`aicomply: cannot read '/nonexistent.txt' (check the path). Try 'aicomply --help'.`

The findings of the inputs that were read decide the exit code: `1` when one is
flagged. When none is, the run exits `2`, as the scan reached no verdict on the file it
could not read; the verdict is `INCOMPLETE`, and the report's verdict line says how many
inputs could not be read. When no input could be scanned, as with a single missing
file, the run ends on a usage error: stderr says why for each input, stdout is empty,
with `--json` too, and the exit code is `2`.

An option name written after `--` (`aicomply scan -- notes.txt -q`) is still a usage
error that ends the run, as the scan would otherwise run without the option.

A file of 2 GiB or more is listed with
`cannot read: it is 2 GiB or larger, and this CLI reads files under 2 GiB`
(on stderr, `cannot read '<file>': ...`).
A smaller file whose text does not decode into one string is listed with
`cannot scan: at <n> bytes it is too large to decode as one input`
(on stderr, `cannot scan '<file>': ...`); on
Node 26.12 that was a file of 629145600 bytes decoded as UTF-8, a UTF-16 file
of 300000000 bytes and a UTF-32 file of 1073741784 bytes of U+1F600 characters.

When stdin is scanned, it is read after the named files, and UTF-8, UTF-16 or
UTF-32 stdin whose text does not decode into one string ends the run on a usage
error, with `cannot scan (stdin): at <n> bytes it is too large to decode as one input`;
on Node 26.12 that was 629145600 bytes decoded as UTF-8
(`head -c 629145600 /dev/zero | aicomply scan`), UTF-16 input of 300000000 bytes
and UTF-32 input of 1073741784 bytes of U+1F600 characters.

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
the writer closes the pipe. The Python CLI also checks, without reading a byte, whether
the pipe is already closed with nothing written, and prints no line then:
`true | aicomply scan clean.txt -q` prints none. A pipe whose writer is still open, or
has not yet written or exited when the check runs, gets the line. The Node CLI cannot
make that check, so it prints the line after a pipe that carries no bytes as well. With
stdin from `/dev/null` (`aicomply scan clean.txt < /dev/null`) neither prints it. A file
with content on
stdin is a usage error (exit `2`) whose message names the form that scans it too,
`aicomply scan - <files>`.
