# Contributing

Thanks for helping make Mimwell better.

## Reporting issues

Open an issue on [GitHub](https://github.com/ConflictHQ/mimwell/issues) with:

- What you ran and what you expected.
- What happened instead, including any error output.
- Your Python, Node and Wrangler versions.

## Pull requests

1. Fork the repository and create a branch.
2. Make your change. Edit sources, never generated artifacts.
3. Run the checks:

    ```sh
    make verify
    ```

4. Open a pull request describing what changed and why.

Keep pull requests focused: one change per request is easiest to review.

## Documentation

These docs live in `docs/` and build with
[MkDocs Material](https://squidfunk.github.io/mkdocs-material/):

```sh
python3 -m pip install mkdocs-material pymdown-extensions
mkdocs serve
```

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](license.md).
