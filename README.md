# replicator

A self-replicating fleet bootstrapper, built as an **application on CE** — no node code, no new
consensus types. It answers one question: *can an app use `rdev` to stand up `rdev`/`swarm`/itself
on other machines and have those machines do the same — securely?* Yes, and this is the reference.

## How it composes CE primitives

| Need | CE primitive used |
|---|---|
| Move binaries to a target | `rdev/sync` (over CE `AppRequest`) |
| Start a real node on a target | `rdev/spawn` (host process, gated by the `spawn` ability) |
| Authorize a replica to replicate onward | `ce-cap` **delegation** (attenuated child capability) |
| A node honor a chain it didn't issue | `ce-cap` **accepted roots** — a shared org key |

## How it scales

A single coordinator fanning work out is **O(N)** (this is what `swarm scatter` does — parallel,
atlas-ranked). Replication turns that into a **tree**: each node we set up gets the `replicator`
binary plus a delegated capability, so it becomes a coordinator for its own sub-tree — **O(log N)
depth** instead of one root doing all the work.

```text
  org root R --[R->A: sync,spawn, exp=T ]--> seed A
    A --push bins--> B --delegate[.. A->B: sync,spawn, exp<T ]--> B   (B can replicate)
      B --push bins--> C --delegate[.. B->C: sync, exp<<T ]--> C       (leaf: no spawn)
```

## Why it's safe: privilege only ever shrinks

Every hop **attenuates** the capability, and `ce-cap::authorize` enforces it at every link:

- **Abilities** are intersected with what a replica needs and can only be a *subset* of the parent.
  `spawn` is dropped at the last level (`depth` reaches 0), so a **leaf can run but not replicate** —
  the recursion terminates by capability, not just by a loop counter.
- **Expiry** is clamped to `min(parent, now+ttl)` — a child can never outlive its parent.
- **Audience** is fixed: a delegated chain names exactly who may use it; a third party presenting a
  stolen chain is rejected.
- The chain is **rooted at the shared org key**. A compromised replica cannot widen its own grant,
  cannot forge a root, and a revoked/expired root collapses the whole subtree.

These properties are unit-tested in `src/main.rs` (attenuation, leaf-can't-spawn, escalation
refused, expiry strictly shrinks across a 3-level tree, impostor rejected) and validated live over
a 3-node mesh in `~/ce-net/e2e-replicate.sh`.

## Use

Each fleet node lists the org root in its accepted roots (`$RDEV_ROOTS` / `<data_dir>/roots`) and
runs `ce start` + `rdev serve`. Then, holding a cap the org root issued you:

```bash
# Push binaries, delegate an attenuated cap, and boot the replica — for each target.
replicator --node http://127.0.0.1:8844 --data-dir ~/.local/share/ce \
  seed <target-node-id> \
  --cap <token rooted at the org key, audience = you> \
  --depth 3 --ttl-secs 1800 \
  --bin rdev=./rdev --bin replicator=./replicator --bin ce=./ce \
  --boot "ce start --no-mine" --boot "rdev serve" --boot "replicator seed ..." \
  --cwd replica

# Dry-run the delegation (no network) — useful for audit/CI:
replicator --data-dir ~/.local/share/ce plan <target-node-id> --cap <token> --depth 3
```

The delegated cap is delivered to the target as `<cwd>/replicator.cap`; the target's own
`replicator seed` uses it to continue the tree, one level weaker.

## Limitation

`spawn` runs native code on the host — it is **not** sandboxed (unlike `rdev/exec`). It exists only
behind the explicit `spawn` ability and is the deliberate, dangerous edge of the primitives-vs-apps
boundary: CE verifies the signature; the app owns the policy of who may spawn what.
