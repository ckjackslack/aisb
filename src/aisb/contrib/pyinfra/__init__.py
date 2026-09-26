"""pyinfra integration: pyinfra ships aisb to your fleet; aisb gives pyinfra a safe, API-level Docker brain.

Because aisb is stdlib-only, it travels as one deterministic `.pyz` (`aisb bundle`) to any host with
Python >= 3.11, over pyinfra's agentless SSH. Three pieces:

- `facts`: read-only aisb ops as pyinfra facts (`AisbDoctor`, `AisbServices`, `AisbStack`, generic `Aisb`);
  mutate/destroy ops are refused there, so a fact can never change a host.
- `operations`: idempotent `install`, `stack`, `limits`; a `ready` gate; `call` for any other op, where
  destroy-tier ops need `confirm=True` (aisb's safety tiers carry over into deploys).
- `connector`: `@aisb/NAME` or `@aisb/stack:NAME` inventory targets that run pyinfra operations *inside*
  containers through the Engine API (exec + archive), without a docker CLI on the controller.

    pip install 'aisb[pyinfra]'
    pyinfra inventory.py deploy.py          # deploy.py: from aisb.contrib.pyinfra import operations as aisb
    pyinfra @aisb/stack:shop exec -- uptime
"""

PYZ = "/usr/local/lib/aisb/aisb.pyz"
PYTHON = "python3"
