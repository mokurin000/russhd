# russhd

*WIP* staticlly linked sshd in Rust, aims to rescue usage.

```bash
ssh -i priv.key -p 2281 -o "UserKnownHostsFile=/dev/null" $(whoami)@127.0.0.1
```