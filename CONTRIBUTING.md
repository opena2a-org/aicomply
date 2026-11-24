# Contributing

Thanks for helping with aicomply. This repository holds two packages: the TypeScript
library and CLI, `@opena2a/aicomply`, at the root, and its Python port, `aicomply`,
under [`python/`](python/).

## Build and test

The TypeScript package:

```bash
npm install
npm run build   # compile to dist/
npm run lint    # type-check
npm test        # jest
```

The Python package, from a virtual environment at the repository root:

```bash
python3 -m venv .venv
.venv/bin/pip install -e "python[dev]"
cd python
../.venv/bin/ruff check src tests bench
../.venv/bin/mypy src/aicomply --ignore-missing-imports
../.venv/bin/python -m pytest -q
../.venv/bin/python bench/measure.py
```

To re-run the measured accuracy of the TypeScript package, see
[docs/accuracy.md](docs/accuracy.md). Report a vulnerability as
[SECURITY.md](SECURITY.md) describes, not in a public issue or pull request.

## License of contributions

aicomply is licensed under the Apache License 2.0 (see [LICENSE](LICENSE)), and
contributions are accepted under the same licence. By contributing, you agree that your
contributions are licensed under the Apache License 2.0.

## Sign your work

Every commit of a contribution carries a sign-off line with your name and email:

```
Signed-off-by: Name <email>
```

`git commit -s` adds it for you. By signing off, you certify the
[Developer Certificate of Origin 1.1](https://developercertificate.org), which reads:

```
Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

No contributor licence agreement is asked for; the sign-off is all. The code licence
does not license the names and logos of the project: the Apache License 2.0 grants no
permission to use them (section 6 of [LICENSE](LICENSE)).
