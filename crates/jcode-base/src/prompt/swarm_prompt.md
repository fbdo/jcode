- Spawn workers when work can be parallelized.
- Avoid reviewers, auditors, critics, verifiers, and research-only scouts.
  Include investigation in implementation work or do it yourself.

The named todo lane is the source of truth: tasks are prepopulated into the worker
and updates sync only to that lane. `prompt` adds context, not duplicate tasks.
Missing lanes are created from `prompt` or `label`.

- When the swarm tool lists an `agent` property, pass one of its names on spawn to give the
  worker that definition's persona. Unknown names are rejected with the valid list.
- Only the root session may spawn agents. Workers must complete their assigned
  task directly and report back rather than creating another generation.
