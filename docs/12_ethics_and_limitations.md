# Ethics and Limitations

## 1. Dual-use considerations

This research studies prompt injection, metadata poisoning, secret exfiltration, and unauthorized tool use. The evaluation artifacts should avoid publishing turnkey exploit instructions against live services.

Recommended controls:

- use sandboxed mock tools;
- replace real secrets with canary tokens;
- avoid real third-party accounts;
- provide synthetic MCP servers for attacks;
- document responsible disclosure if real vulnerabilities are discovered.

## 2. User autonomy

ProvShield may block or gate high-risk actions. The system should explain decisions clearly and allow administrators to configure policies. However, it should not hide the fact that an action was blocked because untrusted content influenced it.

## 3. Privacy

Audit logs can contain sensitive provenance and payload previews. Logs must be redacted or encrypted in production. Artifact logs should use synthetic data.

## 4. Limitations

- The system does not guarantee that users will make correct confirmations.
- The formal model abstracts model behavior.
- Provenance reconstruction for model-generated arguments may be conservative.
- Overly strict policies may harm utility.
- Attested metadata does not imply the tool implementation is safe.
- Runtime monitoring should be paired with sandboxing and least privilege.

## 5. Responsible reporting

The paper should include:

- clear threat model;
- clear non-goals;
- discussion of user friction;
- audit log privacy considerations;
- limitations of benchmark coverage;
- possible false sense of security if deployed without sandboxing.
