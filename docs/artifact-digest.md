# Artifact digest, version 1

This document defines the `digest` value in a provenance record
(`.acb-provenance.yaml`, see [ACB-PROV-001](controls/ACB-PROV-001.md)) and the
value [ACB-PROV-002](controls/ACB-PROV-002.md) recomputes. It is versioned
separately from the controls: a change to anything below is a new version
with a new prefix, never an edit to this one.

## Algorithm

Version 1 is the `h1:` directory hash of Go's
`golang.org/x/mod/sumdb/dirhash` package (`Hash1`, as of commit
`ae88a97cb46b420618fb1d363fbe3343fc4e4613`), applied to the artifact
directory with an empty name prefix. An artifact is a skill directory (the
directory holding `SKILL.md`) or an extension package root.

1. List every regular file under the artifact directory, recursively. A
   file's name is its path relative to the artifact directory, with `/`
   separators and no leading `./`.
2. Leave out two entries directly in the artifact directory, and nothing
   else: `.acb-provenance.yaml`, because a record cannot contain its own
   digest, and `.git` with everything under it, file or directory, because
   an extension package at a repository root would otherwise hash the
   repository's own history. A provenance record or `.git` deeper in the
   tree, such as in a skill inside an extension package, is content and
   stays in.
3. Sort the names by their UTF-8 bytes.
4. For each name in that order, write one summary line: the lowercase
   hexadecimal SHA-256 of the file's bytes, two spaces (U+0020), the name,
   and a newline (U+000A).
5. The digest is `h1:` followed by the standard base64 encoding, with
   padding, of the SHA-256 of the summary. It is always 47 characters.

Directories contribute only through the files they hold, so an empty
directory changes nothing. File contents are hashed as stored: no line-ending
or encoding normalisation.

## When there is no digest

The digest is not computable, and ACB-PROV-002 reports the artifact as not
evaluated, when the artifact directory is or contains:

- a symlink (ACB-SKILL-003 already fails a skill for this);
- anything other than a regular file or directory, such as a FIFO or socket;
- a name that is not valid UTF-8 or that contains a newline;
- a file or directory the checker cannot read.

## What version 1 does not cover

- File modes. Making a file executable, or removing the bit, does not change
  the digest. ACB-SKILL-003 inspects executable files separately.
- Anything outside the artifact directory, including files a skill
  references with `..`, which ACB-SKILL-003 fails.
- Who produced the record. The record sits inside the artifact, so anyone
  who can change the artifact can recompute and replace its digest. A match
  shows the content is the content the record describes, not that the
  publisher released it.

## Reproducing a digest

With Go, `dirhash.HashDir(dir, "", dirhash.Hash1)` gives the same value when
the directory holds neither `.acb-provenance.yaml` nor `.git`; otherwise list
the files with `dirhash.DirFiles(dir, "")`, drop `.acb-provenance.yaml`,
`.git` and every name under `.git/`, and call `dirhash.Hash1` on the rest.

With GNU coreutils, for an artifact that has no symlinks and no file name
containing a backslash or newline (which `sha256sum` escapes):

```sh
cd path/to/artifact &&
  find . -path ./.git -prune -o -type f ! -path ./.acb-provenance.yaml -printf '%P\0' |
  LC_ALL=C sort -z | xargs -0 -r sha256sum | sha256sum |
  cut -d ' ' -f 1 | xxd -r -p | base64 | sed 's/^/h1:/'
```
