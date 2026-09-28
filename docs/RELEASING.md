# Releasing aisb

Releases are cut from a tag; `.github/workflows/release.yml` does the rest.

## Every release

1. Bump `__version__` in `src/aisb/__init__.py` (the package version is read from it), and add a
   `## [X.Y.Z] - date` section to `CHANGELOG.md`: it becomes the release notes (generated notes otherwise).
2. Commit, push, and wait for `ci` to be green on that commit.
3. Release it, either way:
   - push a tag:

     ```bash
     git tag -a v0.3.0 -m "aisb 0.3.0"
     git push origin v0.3.0
     ```

   - or, without a local checkout, go to *Actions → release → Run workflow*, pick the branch and enter
     `v0.3.0`. The tag is created on that branch's head commit.

The `release` workflow then:

- checks that the tag matches `__version__`;
- runs the unit tests;
- builds the sdist, the wheel and the single-file `aisb.pyz`, plus `SHA256SUMS`;
- publishes a GitHub release with all of them, using the version's `CHANGELOG.md` section as notes. A release drafted in the GitHub UI gets the
  files attached, and an already-published release is never rewritten;
- publishes the sdist and wheel to PyPI, but only when PyPI publishing is enabled (see below).

## One-time: enable PyPI trusted publishing

No API token is stored anywhere; PyPI trusts this workflow's OIDC identity.

1. On PyPI, open *Your account → Publishing → Add a new pending publisher* and fill in:
   - **PyPI project name:** `aisb`
   - **Owner / repository:** `ckjackslack` / `aisb`
   - **Workflow name:** `release.yml`
   - **Environment name:** `pypi`
2. On GitHub, open *Settings → Environments* and create an environment named `pypi`. Optionally add yourself
   as a required reviewer, so every PyPI upload waits for a click.
3. On GitHub, open *Settings → Secrets and variables → Actions → Variables* and add `PYPI_PUBLISH` = `true`.
4. To publish a tag that already exists, open *Actions → release → Run workflow* and enter the tag (e.g. `v0.2.0`).
   The GitHub release is left as it is, and versions already on PyPI are skipped.

PyPI versions are immutable: a version number can be uploaded once, never replaced. Fix mistakes with a new
patch release.
