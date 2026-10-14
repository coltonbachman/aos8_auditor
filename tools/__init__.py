"""Development tools. Not part of the shipped package — see tools/README.md.

Importable as ``tools.*`` because the repo root is on sys.path under pytest
(conftest.py), which is how tests/test_command_lines_pinned.py shares this
package's idea of "every line the catalog can send" with the validator that
checks those lines against a controller. One definition, two readers.
"""
