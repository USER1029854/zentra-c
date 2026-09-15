# findings.md — Zentra / ctUSD reserve audit

- **Target:** ctUSD reserve (M backing) on Citrea mainnet (chainId 4114), pin block 12,670,209.
- **In-lane findings (outsider value-theft):** **NONE** (proven or UNPROVEN).
- **Verdict:** CLEAN for the audited scope. Reserve exactly fully backed
  (`totalSupply + yield == M.balanceOf(ctUSD)`); every exit gated by privileged EOAs/roles or 1:1
  conservation; ctUSD/SwapFacility byte-identical to canonical M^0 v1.0.0; money market a faithful,
  currently-paused Aave V3 fork with non-manipulable oracles.

## Findings
_(none — empty set)_

## Out-of-lane risks recorded (NOT outsider-theft findings)
| id | class | where | value at risk | outsider-exploitable? | note |
|----|-------|-------|---------------|-----------------------|------|
| R1 | centralization | ctUSD FREEZE + FORCED_TRANSFER = one EOA `0x2a5c…1f32` | up to full ~$4.9M ctUSD supply (freeze+seize any holder) | No (privileged EOA, not acquirable) | #1 trust risk; recommend splitting roles + timelock/multisig |
| R2 | upgrade/key | ctUSD & SwapFacility proxy admins (EOA-owned); MToken `migrate()` | entire reserve | No (key compromise) | move upgrade rights behind a timelocked multisig |
| R3 | dependency | M backing minted by SpokePortal from Hyperlane-bridged M | entire reserve | No (bridge infra) | backing integrity = Hyperlane default ISM + hub lock; verify ISM validator set |
| R4 | DoS | ZentraOracle has no fallback (`getFallbackOracle()=0x0`) | money-market solvency | No (griefing, no beneficiary) | stale feed reverts liquidationCall → bad-debt; market currently paused |

## Value at risk (live, re-read at head)
- ctUSD reserve: **4,915,658.588239 M ≈ $4.9M**, exactly backing `totalSupply 4,909,789.488926` + `yield 5,869.099313`.
- Money market (paused): ~$3.5M supplied, ~$0.2M immediately borrowable — not outsider-extractable.

## Proof state
- Gating fork-verified on anvil @12,670,209 (unprivileged wrap/unwrap/unwrap-direct revert;
  claimYield pays only the fixed yieldRecipient).
- Reconciliation verified at pin and head.
- Fork-drift diffs vs canonical M^0 (evm-m-extensions v1.0.0, common) and Aave v3-core: value-critical
  code byte-identical.
