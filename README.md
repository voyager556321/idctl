# idctl

Ever committed code with the wrong Git identity?

Ever deployed to the wrong AWS account?

Ever wondered which SSH key your terminal will actually use?

`idctl` is a read-only CLI that inspects your runtime identity context across Git, AWS, Kubernetes and SSH, then highlights mismatches and risks before they become mistakes.

## Example

```bash
idctl risk
```

```text
LOW

SSH identity mismatch

Problem:
Expected key ~/.ssh/id_personal is not loaded in ssh-agent

Impact:
SSH connections may authenticate as another identity

Fix:
ssh-add ~/.ssh/id_personal
```

## Why?

Modern developer environments contain multiple identities:

* Git accounts
* AWS profiles
* Kubernetes contexts
* SSH keys

`idctl` helps you understand which identity is actually active right now.
