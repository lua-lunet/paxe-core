# Agent Instructions

## Authorship and Git Safety

You MUST NOT advertise with any branding in any message or `Co-authored-by`
trailer: the repository owner is the legal owner and author, and agents are
probabilistic tools.

Do not commit unless explicitly asked to. Do not push unless explicitly asked
to.

Do not use `git reset`, `git stash`, `git rm`, `rm`, or another operation that
might delete work from the user or other agents. When a soft deletion is
needed, move the target to the repository's gitignored `.tmp/` directory.
