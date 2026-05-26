# Ablation Plan

## A0: Full ProvShield

All components enabled.

## A1: No provenance labels

Disable label tracking and rely on prompt-rendered boundaries. Expected: label spoofing and indirect injection success increase.

## A2: No runtime monitor

Keep labels but do not enforce source-to-sink policy. Expected: labels alone do not prevent attacks.

## A3: No bridge binding

Replace bound bridge with generic confirmation. Expected: confirmation laundering and payload swap attacks succeed.

## A4: Trust tool metadata by default

Treat all MCP metadata as trusted. Expected: MCP metadata poisoning success increases.

## A5: No capability token

Allow user confirmation without one-time runtime token. Expected: replay and destination/payload swap risk increases.

## A6: Confidentiality only

Remove integrity checks. Expected: secret exfiltration may reduce, but unauthorized writes and control-flow attacks persist.

## A7: Integrity only

Remove confidentiality checks. Expected: unauthorized control reduces, but private/secret leakage increases.

## A8: No audit replay

Disable replayable logs. Expected: security may remain but artifact and forensic quality degrade.

## Reporting

For each ablation, report:

- ASR by suite;
- BTCR;
- false blocking;
- bridge burden;
- key failure examples.
