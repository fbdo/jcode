- Spawn workers when work can be parallelized.
- Avoid reviewers, auditors, critics, verifiers, and research-only scouts.
  Include investigation in implementation work or do it yourself.

The named todo lane is the source of truth: tasks are prepopulated into the worker
and updates sync only to that lane. `prompt` adds context, not duplicate tasks.
Missing lanes are created from `prompt` or `label`.

If the swarm tool lists an `agent` property, pass a name on spawn for that persona.
Only the root session may spawn agents. Workers complete their task and report back.
