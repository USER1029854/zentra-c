# Zentra Finance / ctUSD — deployed-protocol value-theft audit

**Target:** the reserve backing the synthetic dollar **ctUSD**, and every path by which value
leaves that reserve or by which ctUSD is minted/redeemed.
**Chain:** Citrea mainnet (chainId **4114**), `https://rpc.mainnet.citrea.xyz`,
explorer `https://explorer.mainnet.citrea.xyz` (Blockscout).
**Pin:** block **12,670,209** (`0xc15701`); dollar figures re-read at head (~12,672,137).
**Method:** blind — derived entirely from deployed/verified source + live state; canonical M^0 / Aave
used only for fork-drift diffing.

---

## 1. Findings (above the verdict)

**No in-lane finding.** After enumerating every exit from the ctUSD reserve, pricing every guard,
reconciling issued-vs-backing to the wei, diffing all deployed code against canonical upstream, and
fork-executing the unprivileged attack paths, **no live, outsider-reachable path was found that lets a
party with no permission take value or control from the ctUSD reserve, or put it at risk** (in the
theft sense of the lane). There is no proven or `UNPROVEN` in-lane structural defect to report.

The material risks that exist are **out of lane** (privileged-party / key-compromise / bridge-infra /
DoS) and are documented in §4–§5 so the team has them, but none is an outsider value-theft path and
none is presented as a finding.

---

## 2. The verdict (with denominators)

**CLEAN** for the audited scope: an unprivileged outsider cannot mint ctUSD unbacked, extract M from
the reserve beyond the ctUSD they burn 1:1, seize another holder's ctUSD, or over-claim yield.

### What the reserve is, and that it balances
- ctUSD `0x8D82c4E3c936C7B5724A382a9c5a4E6Eb7aB6d5D` is a **M^0 `MYieldToOneForcedTransfer`** extension
  (impl `0xF15E4De6…804C`) that wraps the M token `0x866A2BF4…be1b` ("M by M0", 6-dec) **1:1**.
- Reserve = M held by ctUSD. **Reconciliation (head):**
  `totalSupply 4,909,789.488926 + yield 5,869.099313 = 4,915,658.588239 = M.balanceOf(ctUSD)` — exact,
  fully backed, small yield surplus. ctUSD holds 99.9998% of all M in existence.
- Value in the reserve ≈ **$4.9M** (M ≈ $1).

### Exits enumerated (closed set), each with 3 cited answers
| Exit | Who can trigger | Q1 auth | Q2 amount/backing | Q3 guard=invariant | Verdict |
|---|---|---|---|---|---|
| **wrap** (mint ctUSD) | SwapFacility only, caller must be permissioned M-swapper for ctUSD | `MExtension.wrap` `onlySwapFacility`; `SwapFacility._swapInM` → `_revertIfNotApprovedSwapper` | mints exactly the M pulled in (`_wrap`→`transferFrom` then `_mint(amount)`) | 1:1, M received before mint | gated (2 EOA swappers) |
| **unwrap** (redeem ctUSD→M) | SwapFacility only, permissioned swapper | `MExtension.unwrap` `onlySwapFacility`; `_swapOutM` → `_revertIfNotApprovedSwapper` | burns ctUSD from SwapFacility, sends `amount` M; rounding favors protocol | burn precedes transfer (non-repeatable) | gated |
| **claimYield** | anyone (public) | n/a | mints `yield()=mBal−totalSupply` (≥0), i.e. only real surplus M | recipient is fixed `yieldRecipient()`, never caller | safe (no attacker gain) |
| **forceTransfer** (seize) | `FORCED_TRANSFER_MANAGER_ROLE`, target must be frozen | role-gated + `_revertIfNotFrozen` | moves existing balance only | 2 privileged roles | privileged (out of lane) |
| **M mint** (backing source) | SpokePortal via a supported bridge adapter | `Portal.receiveMessage` requires `msg.sender ∈ supportedBridgeAdapter`; adapter `handle()` requires `msg.sender==mailbox && sender==peer` | mints amount from an authenticated cross-chain message; replay-protected | app-layer checks sound | gated (bridge infra dependency) |

**Fork-verified (anvil @12,670,209):** unprivileged `swapOutM(ctUSD,…)` / `swapInM(ctUSD,…)` revert
`NotApprovedPermissionedSwapper` (`0xe5fae0d0`); direct `ctUSD.unwrap(attacker,…)` reverts
`NotSwapFacility` (`0x2bfe1b5c`); `claimYield()` mints only to the yieldRecipient Safe.

### Code provenance (fork-drift, both ways)
- ctUSD `MExtension`, `MYieldToOne`, and all signature/permit common libs (`ERC3009Upgradeable`,
  `ERC20ExtendedUpgradeable`, `ERC712ExtendedUpgradeable`, `SignatureChecker`) are **byte-identical to
  canonical M^0** (evm-m-extensions v1.0.0 / common). The `SwapFacility` (impl `0xD87c75…`) is
  **byte-identical** to canonical v1.0.0.
- The `ForcedTransferable`/`Freezable`/`Pausable` components on ctUSD are an *older* M^0 revision; the
  only behavioral delta is that `claimYield()` lacks the newer `_requireNotPaused()` and
  `setYieldRecipient` claims-then-sets — both privileged, neither a theft path.
- MToken is a faithful **spoke** M^0 token (mint/burn `onlyPortal`, index pushed by Portal, monotonic
  with a `DecreasingIndex` guard). Registrar writes are `onlyPortal`.
- Money market (see §5) is a faithful Aave V3 fork with byte-identical value-logic.

**Completeness:** 5 exits, all with three cited answers; guard register priced (§4); issued≤backing
reconciled to the wei; the reserve-management set (minters, swappers, role-holders, M-holders) was
reconstructed from events, not sampled. The verdict is **whole**, not time-boxed-partial, for the
ctUSD-reserve scope. The money-market layer was covered as an adjacent "value-leaves-the-reserve"
surface and is likewise clean (currently paused).

---

## 3. What this audit cannot see
On-chain logic only. It says nothing about the ctUSD/SwapFacility/Portal **admin keys**, the
**off-chain market-maker** operating the two permissioned-swapper EOAs, the **Hyperlane validator
set** securing M minting, or the **RedStone/Stork oracle operators**. "Clean" here means the code has
no open outsider exit — not that the keys/operators/bridge are safe.

---

## 4. Guard register (dollar-priced)
| Guard | Protects | Held by | Acquisition cost to an outsider |
|---|---|---|---|
| ctUSD `DEFAULT_ADMIN` + `FREEZE_MANAGER` + `FORCED_TRANSFER_MANAGER` | freeze + seize any ctUSD | **single EOA** `0x2a5c…1f32` | key compromise only — **not acquirable** on-chain |
| ctUSD permissioned M-swapper (wrap/unwrap) | mint/redeem ctUSD | 2 EOAs `0x5d238f…`, `0x4743a4…` | set by SwapFacility admin — not acquirable |
| SwapFacility `DEFAULT_ADMIN` | approve/permission extensions & swappers | EOAs `0xf2f1acbe`, `0x8f4f10…` | not acquirable |
| ctUSD / SwapFacility proxy upgrade | full logic | ProxyAdmins owned by `0x55a8103…` / migrationAdmin `0x8C645e20…` | not acquirable |
| SpokePortal `OPERATOR` (bridge adapters/peers) + `DEFAULT_ADMIN` (upgrade) | M minting trust config | deployer EOA / migrationAdmin | not acquirable |
| M mint | new backing | SpokePortal ← Hyperlane mailbox `0x3a464f7…` + peer | forge a Hyperlane message past the default ISM (bridge infra) |

Every fund-moving guard resolves to a privileged EOA/Safe or bridge infrastructure. **No role,
majority, or whitelist entry is buyable/bondable by an outsider** (no governance token, no permissionless
grant). So no guard has a dollar price below what it protects that an outsider can pay.

---

## 5. Out-of-lane risks & dependencies (documented, not findings)
1. **Single-key seize (largest value-at-risk).** ctUSD's `FREEZE_MANAGER_ROLE` and
   `FORCED_TRANSFER_MANAGER_ROLE` are both the one EOA `0x2a5c…1f32`. It can freeze any account and
   `forceTransfer` its **entire** ctUSD balance — up to the full ~$4.9M supply, including balances
   held by the Morpho vaults, the Algebra DEX pools, and the money-market aToken. This is a compliance
   feature, but with both roles on one un-timelocked EOA it is unilateral seizure of all ctUSD.
   *Out of lane (privileged, key not acquirable); the #1 trust risk to flag.*
2. **Upgrade authority** over ctUSD and the SwapFacility sits behind EOA-owned ProxyAdmins; MToken has
   an admin `migrate()`. A compromised admin key drains everything. *Key-compromise / out of scope.*
3. **Backing = a Hyperlane bridge.** M is minted by the SpokePortal from Hyperlane-bridged M; ctUSD's
   backing is only as sound as Hyperlane's ISM and the hub-side lock. The app-layer receive path is
   correctly gated (`msg.sender==mailbox && sender==peer` + replay). The mailbox default ISM
   `0x61dbB636…` is a **2-of-2 aggregation** of a domain-routing ISM (`0xf89621…`, type ROUTING →
   per-origin validator multisig) **and** a null-type module (`0xd8B9…`, owner-configured); because
   both are required, the security floor is the hub-domain validator multisig, so **an outsider cannot
   forge an M mint** without defeating that multisig. Residual trust = that validator set and the ISM
   admin `0x4fC003a3…` (bridge infra; validator roster/admin not fully enumerated here).
4. **Money market (Aave V3 fork, Pool `0xfb79…06F5`, oracle `ZentraOracle 0xd8A0…8144`).** Faithful
   fork (value-logic byte-identical, external libs re-verified at deployed addresses); prices are
   RedStone push (USDC/WCBTC), Stork+CAPO upside-cap (sUSN), static $1 (ctUSD) — **none
   DEX/atomically manipulable**; configs conservative; the only modification is an **additive,
   fail-closed hook system** (can only block, never move funds). **All four reserves are currently
   `paused` (dormant).** Residual: the oracle has **no fallback**, so a stale feed reverts
   `liquidationCall` → bad-debt risk (DoS, out of lane). No outsider drain path.

---

## 6. Null Report — the three places a missed bug most likely hides (ranked by cost-if-wrong)
1. **SpokePortal's Hyperlane validator roster (largely closed).** The ISM is a sound 2-of-2
   aggregation with a hub-domain routing multisig, so a forged mint needs the multisig defeated — not
   an outsider capability. What I did **not** enumerate: the routing ISM's actual domain-1 validator
   addresses/threshold and the ISM admin `0x4fC003a3…`'s controls. A misconfigured (e.g. 1-of-1
   self-owned) validator set would reopen forged-mint → unbacked ctUSD. *Settle it:* enumerate the
   domain-1 multisig validators + threshold and the admin's timelock/multisig status.
2. **Two unverified contracts in adjacent price/hook paths:** the ctUSD money-market price feed
   `0x2CbFF2093…` (behaves as a static $1 feed on every call I made) and the Pool hook
   `SecurityIntegrationV2 0x9dF4BaCB…` (fail-closed, cannot move funds by construction). Behavior was
   confirmed externally but neither was decompiled. *Settle it:* decompile both; confirm the feed is
   unconditionally static and the hook has no fund-moving/authorization side effect.
3. **The money market once unpaused.** The clean verdict there was reached against a paused market and
   push-oracle reads. *Settle it:* on a fork, unpause and run a full supply→borrow→price-move→liquidate
   cycle against each collateral, fuzzing feed timing/return values at the staleness and CAPO edges.

---
*Evidence (recovered source, diffs, fork logs, register) saved under the audit scratchpad.*
