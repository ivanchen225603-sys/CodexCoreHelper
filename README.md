# CodexCoreHelper

CodexCoreHelper is a reusable Codex Skill for coordinating requirements, architecture,
prototyping, implementation, review, verification, CI/CD, deployment, and operations through
deterministic gates and auditable evidence.

## Restore on another Windows device

1. Clone this repository to `C:\Users\<username>\.codex\skills\codex-core-helper`.
2. Install the deterministic runtime dependencies:

   ```powershell
   py -m pip install -r scripts\requirements.txt
   ```

3. Restart Codex and invoke the Skill as `$codex-core-helper`.
4. Configure the project-specific trusted root and the host-managed approval trust bundle before
   executing repository commands or recording human approvals.

## Security

Do not commit private signing keys, credentials, `.env` files, or host-specific approval trust
bundles. Keep approval keys and trust configuration outside both the project repository and this
Skill repository.
