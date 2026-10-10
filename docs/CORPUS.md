# Corpus handling

SandboxHawk accepts directories containing `.js` files and walks them recursively. Empty files and files larger than `-max-bytes` are skipped. It skips common generated directories (`.git`, `node_modules`, `crashes`, `artifacts`).

For an initial run, standalone JavaScript files work best. V8 test suites often use `load()`, `loadRelativeToScript()`, `d8.file.execute()`, mjsunit helpers, shell-specific flags, or native syntax. This MVP does not resolve those dependencies or strip harness calls; those seeds may fail and should be adapted carefully. Keep an untouched copy of each original seed for reproducibility.

The upstream loader you shared uses Babel AST transformations to resolve dependencies and normalize scripts. Regex-only rewriting is deliberately avoided here because it can change test semantics.
