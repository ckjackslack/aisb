# aisb-owners: an example aisb plugin

A complete, installable plugin in about 70 lines. Use it as a template: copy the directory, rename the package,
and replace the ops.

```bash
pip install ./examples/aisb-owners          # or: pip install -e ./examples/aisb-owners
aisb owners list -o table                   # containers grouped by their com.example.owner label
aisb owners stop-unowned --keep db --dry-run
aisb containers doctor web                  # now also reports "no-owner"
```

## What a plugin is

A Python module that aisb imports. It is found in any of three ways:

| Source | Use it for |
|---|---|
| the `aisb.plugins` entry-point group (see `pyproject.toml`) | installed packages |
| `AISB_PLUGINS=module_a,module_b` | trying a module on `PYTHONPATH` without installing it |
| `[plugins] modules = ["module_a"]` in `~/.aisb/config.toml` | pinning plugins per machine or profile |

Importing the module is the whole protocol. An optional module-level `setup()` is called once. A plugin that fails
to import never breaks aisb; `aisb config show` lists each plugin as `ok` or with its error.

## What you can register

- **Resources and ops**: subclass `aisb.ops.Resource` with a `name=` and decorate methods with `@op(Tier.X)`.
  Type hints become flags: `Annotated[type, "help"]`, keyword-only for `--flags`, positional otherwise;
  `list[str]` is a repeatable flag; `Literal[...]` gives choices. The docstring's first line is the summary.
  Each op then gets the CLI, MCP tools, the portal, `aisb docs`, man pages and shell completion
  (regenerate them after installing), policy rules and audit records.
- **Tiers**: `READ` runs freely; `MUTATE` gets `--dry-run`; `DESTROY` previews and exits 3 until `--yes`.
  Under `--dry-run`, GETs run and every other request is recorded instead of sent, so an op is previewed
  without extra code. Side effects outside Docker (files, network) should check `self.t.planning` and call
  `self.t.note(...)` instead.
- **Doctor rules**: `@aisb.insights.triage.rule` on a function from `Facts` to `Finding`s.
- **Service adapters**: `@aisb.services.base.register` on an `Adapter` subclass teaches `svc`, `db`
  and friends a new server.

## Tests

```bash
pip install -e "./examples/aisb-owners[dev]" && pytest examples/aisb-owners/tests
```

aisb's own suite also runs this plugin end to end against its fake Docker daemon
(`tests/test_example_plugin.py`): the CLI, dry runs, MCP tools, policy and audit.
