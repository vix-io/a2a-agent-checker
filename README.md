# a2a-agent-checker

Check a domain's [A2A](https://a2a-protocol.org) Agent Card against the v1.0
specification.

```
$ a2a-check stillopen.work --probe
stillopen.work: PASS  (StillOpen)
  https://stillopen.work/.well-known/agent-card.json
  info  endpoint https://stillopen.work/api/v1/a2a answers JSON-RPC and reports an unknown task correctly (-32001)
```

## Install

```
pip install git+https://github.com/vix-io/a2a-agent-checker
```

## What it checks

- The card exists at `/.well-known/agent-card.json`, over HTTPS, as JSON.
- Every field v1.0 requires is present and the right type: `name`,
  `description`, `supportedInterfaces`, `version`, `capabilities`,
  `defaultInputModes`, `defaultOutputModes`, `skills`.
- Each interface is HTTPS, names a known binding (`JSONRPC`, `GRPC`,
  `HTTP+JSON`) and a protocol version.
- Each skill has an `id`, `name`, `description` and `tags`; ids are unique.
- Common mistakes: a 0.3-era card (top-level `url`, `preferredTransport`),
  snake_case keys, an endpoint on a different host from the card.

With `--probe` it also asks each endpoint on the card's own host for a task
that cannot exist (`GetTask` with a random id):

- **JSONRPC**: a conforming agent answers error `-32001` (TaskNotFound).
- **HTTP+JSON**: `GET {url}/tasks/{id}` (with the interface's `tenant`
  prefixed when set); a conforming agent answers HTTP 404 with a
  `google.rpc.Status` body whose `ErrorInfo.reason` is `TASK_NOT_FOUND`. A
  bare 404 is reported as a warning, since it is also what a server returns
  for a route that does not exist.
- **GRPC** is not probed.

This is the most harmless call A2A defines: nothing is created or run on the
other side. The checker never sends `SendMessage`, and never probes an
endpoint on a different host from the card.

Card signatures are reported but not yet verified.

## Results

Each finding is `fail` (a v1.0 client cannot use the card), `warn` (usable,
but something will trip a client or a person) or `info`. The exit status is
1 if any domain fails, otherwise 0. `--json` prints machine-readable output.

## Library

```python
from a2a_agent_checker import check, validate

report = check("example.com", probe=True)
print(report.verdict, [f.message for f in report.findings])

findings = validate(card_dict, "https://example.com/.well-known/agent-card.json")
```

## Safe to run on untrusted input

The checker is built to sit behind a public web form, so every URL is
treated as hostile:

- HTTPS on port 443 only; no IP literals, no credentials in URLs.
- The name is resolved once, every address must be public, and the
  connection goes to that checked address (the name is kept for TLS). This
  closes the DNS-rebinding gap where a second lookup returns `127.0.0.1`.
- Redirects are followed by hand, each hop re-checked, at most 3.
- 10-second timeouts and a 256 KB response cap.

Rate-limiting visitors is the host application's job.

## Licence

Apache 2.0.
