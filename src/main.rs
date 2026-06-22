//! replicator — a self-replicating fleet bootstrapper, built as an **application on CE**.
//!
//! It composes two CE building blocks and adds NO node code:
//!   - **rdev** (`rdev/sync` + `rdev/spawn`, over CE `AppRequest`) — ship binaries to a target and
//!     start host processes there (so a target becomes a real, mesh-addressable CE node).
//!   - **ce-cap** delegation — hand each replica a *strictly weaker* capability than the one we
//!     hold, signed by us, chained to its parent. A node honors the chain because it roots at a
//!     **shared org key** every fleet node lists in `<data_dir>/roots`.
//!
//! ## How it scales (and stays safe)
//! A single coordinator fanning out is O(N). Replication makes it a *tree*: each node we set up
//! receives a delegated cap and the `replicator` binary, so it becomes a coordinator for its own
//! sub-tree — O(log N) depth. The **capability attenuates at every hop**: shorter expiry, and the
//! `spawn` ability is dropped at the last level (`depth` reaches 0), so a leaf can run but cannot
//! replicate further. Privilege can only ever shrink down the tree — `ce-cap::authorize` enforces
//! that every link is no broader than its parent, so a compromised replica cannot widen its grant.
//!
//! ```text
//!   org root R  --[R->A: sync,spawn, exp=T]-->  seed A
//!     A  --push replicator+rdev+ce--> B   --delegate [.. A->B: sync,spawn, exp<T]-->  B
//!       B  --push ...--> C  --delegate [.. B->C: sync, exp<<T]-->  C   (no spawn: leaf)
//! ```

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use ce_cap::{Caveats, SignedCapability, decode_chain, encode_chain};
use ce_identity::{Identity, NodeId};
use ce_rs::CeClient;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

/// The abilities a replica needs to keep replicating: receive files (`sync`) and start the node +
/// serve + replicator (`spawn`). A leaf keeps `sync` (so it can still receive work) but loses
/// `spawn`. Any ability the parent doesn't hold is filtered out — delegation can never add power.
const REPLICATION_ABILITIES: [&str; 2] = ["sync", "spawn"];

#[derive(Parser)]
#[command(name = "replicator", version, about = "Self-replicating CE fleet bootstrapper (an app on rdev + ce-cap)")]
struct Cli {
    /// Local CE node API URL (default http://127.0.0.1:8844).
    #[arg(long, global = true, default_value = "http://127.0.0.1:8844")]
    node: String,
    /// CE data dir holding the identity that SIGNS delegations (default ~/.local/share/ce).
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Replicate onto each target: push binaries, delegate an attenuated cap, spawn boot commands.
    Seed {
        /// Target node ids (64-hex), each already running a CE node + `rdev serve` that lists our
        /// chain's root in its accepted roots.
        targets: Vec<String>,
        /// Our capability chain (audience = us) authorizing `sync`+`spawn` on the targets.
        #[arg(long)]
        cap: String,
        /// Replication depth. The cap we delegate lets a target replicate only while depth > 1;
        /// at the last hop `spawn` is dropped, so the tree terminates.
        #[arg(long, default_value = "1")]
        depth: u32,
        /// Time-to-live (seconds) for the delegated cap; clamped to never outlive the parent.
        #[arg(long = "ttl-secs", default_value = "3600")]
        ttl: u64,
        /// Binary to push as `name=local/path` (repeatable); lands at `<cwd>/name` on the target.
        #[arg(long = "bin")]
        bins: Vec<String>,
        /// Shell command to spawn on the target (repeatable), e.g. `--boot "ce start --no-mine"`.
        #[arg(long = "boot")]
        boot: Vec<String>,
        /// Remote working directory under the target's home (delegated cap delivered here too).
        #[arg(long, default_value = "replica")]
        cwd: String,
    },
    /// Print the delegated cap that WOULD be issued for a target — no network. For audit/CI.
    Plan {
        /// Target node id (64-hex).
        target: String,
        #[arg(long)]
        cap: String,
        #[arg(long, default_value = "1")]
        depth: u32,
        #[arg(long = "ttl-secs", default_value = "3600")]
        ttl: u64,
    },
}

// ---------- wire types (mirror rdev's Req/Resp) ----------

#[derive(Debug, Serialize, Deserialize, Default)]
struct Req {
    caps: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    data_hex: Option<String>,
    #[serde(default)]
    cmd: Option<Vec<String>>,
    #[serde(default)]
    cwd: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct Resp {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    stdout: Option<String>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ---------- delegation: the security spine (pure, fully unit-tested) ----------

/// Abilities to grant a child. Intersect the parent's abilities with what a replica needs, and
/// drop `spawn` unless the child is allowed to replicate further. The result is always a subset of
/// the parent's abilities, so `ce-cap` attenuation accepts it and privilege can only shrink.
fn onward_abilities(parent_abilities: &[String], child_can_replicate: bool) -> Vec<String> {
    parent_abilities
        .iter()
        .filter(|a| REPLICATION_ABILITIES.contains(&a.as_str()))
        .filter(|a| child_can_replicate || a.as_str() != "spawn")
        .cloned()
        .collect()
}

/// Narrow a parent's caveats for a child: expiry clamped to `min(parent, now+ttl)` (a child may
/// never outlive its parent), everything else inherited unchanged. The result is always
/// `narrower_or_equal` to the parent, which `ce-cap` requires.
fn attenuate(parent: &Caveats, now: u64, ttl: u64) -> Caveats {
    let want_exp = now.saturating_add(ttl);
    let not_after = match parent.not_after {
        0 => want_exp,               // parent never expires → child still gets a finite ttl
        p => p.min(want_exp),        // never outlive the parent
    };
    Caveats { not_after, ..parent.clone() }
}

/// Extend `parent_chain` with a delegated capability for `child`, signed by `holder` (who MUST be
/// the audience of the last cap in the chain). Returns the full chain `[..parent, child]` — which
/// `ce-cap::authorize` accepts for `child`, rooted at the same root as the parent.
fn delegate(
    parent_chain: &[SignedCapability],
    holder: &Identity,
    child: NodeId,
    child_can_replicate: bool,
    now: u64,
    ttl: u64,
    nonce: u64,
) -> Result<Vec<SignedCapability>> {
    let parent = parent_chain.last().ok_or_else(|| anyhow!("empty capability chain"))?;
    if parent.cap.audience != holder.node_id() {
        bail!("cannot delegate: the signing identity is not the audience of the held capability");
    }
    let abilities = onward_abilities(&parent.cap.abilities, child_can_replicate);
    if abilities.is_empty() {
        bail!("nothing to delegate: parent holds none of {REPLICATION_ABILITIES:?}");
    }
    let caveats = attenuate(&parent.cap.caveats, now, ttl);
    let child_cap = SignedCapability::issue(
        holder,
        child,
        abilities,
        parent.cap.resource.clone(),
        caveats,
        nonce,
        Some(parent.id()),
    );
    let mut chain = parent_chain.to_vec();
    chain.push(child_cap);
    Ok(chain)
}

// ---------- runtime ----------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let data_dir = cli.data_dir.clone().unwrap_or_else(default_data_dir);
    match cli.cmd {
        Cmd::Plan { target, cap, depth, ttl } => {
            let identity = Identity::load_or_generate(&data_dir.join("identity"))?;
            let chain = decode_chain(&cap).map_err(|_| anyhow!("bad --cap token"))?;
            let child = parse_node_id(&target)?;
            let onward = delegate(&chain, &identity, child, depth > 1, now(), ttl, now())?;
            let leaf = onward.last().unwrap();
            println!("delegated cap for {target}:");
            println!("  abilities : {:?}", leaf.cap.abilities);
            println!("  expires   : {} (now={})", leaf.cap.caveats.not_after, now());
            println!("  chain len : {}", onward.len());
            println!("  token     : {}", encode_chain(&onward));
            Ok(())
        }
        Cmd::Seed { targets, cap, depth, ttl, bins, boot, cwd } => {
            let client = CeClient::new(cli.node.clone());
            if !client.health().await.unwrap_or(false) {
                bail!("local CE node not reachable at {} — is `ce start` running?", cli.node);
            }
            let identity = Identity::load_or_generate(&data_dir.join("identity"))?;
            let our_chain = decode_chain(&cap).map_err(|_| anyhow!("bad --cap token"))?;
            let mut nonce = now();
            let mut ok = 0usize;
            for target in &targets {
                nonce += 1;
                match replicate_to(&client, &identity, &our_chain, &cap, target, depth, ttl, &bins, &boot, &cwd, nonce).await {
                    Ok(()) => {
                        ok += 1;
                        println!("replicated -> {}", &target[..target.len().min(16)]);
                    }
                    Err(e) => eprintln!("FAILED {} : {e}", &target[..target.len().min(16)]),
                }
            }
            println!("seeded {ok}/{} target(s)", targets.len());
            if ok == targets.len() { Ok(()) } else { Err(anyhow!("{} target(s) failed", targets.len() - ok)) }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn replicate_to(
    client: &CeClient,
    identity: &Identity,
    our_chain: &[SignedCapability],
    our_cap: &str,
    target: &str,
    depth: u32,
    ttl: u64,
    bins: &[String],
    boot: &[String],
    cwd: &str,
    nonce: u64,
) -> Result<()> {
    let child = parse_node_id(target)?;
    // 1. push binaries (our cap authorizes us to sync on the target).
    for spec in bins {
        let (name, path) = spec.split_once('=').ok_or_else(|| anyhow!("--bin must be name=path"))?;
        let data = std::fs::read(path).with_context(|| format!("read {path}"))?;
        sync(client, target, our_cap, &format!("{cwd}/{name}"), &data).await?;
    }
    // 2. delegate an attenuated cap the target uses to replicate onward, and deliver it.
    let onward = delegate(our_chain, identity, child, depth > 1, now(), ttl, nonce)?;
    let onward_token = encode_chain(&onward);
    sync(client, target, our_cap, &format!("{cwd}/replicator.cap"), onward_token.as_bytes()).await?;
    // 3. spawn boot commands on the target (our cap authorizes us to spawn there).
    for line in boot {
        let argv: Vec<String> = line.split_whitespace().map(|s| s.to_string()).collect();
        if argv.is_empty() {
            continue;
        }
        spawn(client, target, our_cap, argv, cwd).await?;
    }
    Ok(())
}

async fn sync(client: &CeClient, node: &str, caps: &str, path: &str, data: &[u8]) -> Result<()> {
    let req = Req { caps: caps.to_string(), path: path.to_string(), data_hex: Some(hex::encode(data)), ..Default::default() };
    let reply = client.request(node, "rdev/sync", &serde_json::to_vec(&req)?, 120_000).await?;
    check(reply, &format!("sync {path}"))
}

async fn spawn(client: &CeClient, node: &str, caps: &str, argv: Vec<String>, cwd: &str) -> Result<()> {
    let req = Req { caps: caps.to_string(), cmd: Some(argv.clone()), cwd: Some(cwd.to_string()), ..Default::default() };
    let reply = client.request(node, "rdev/spawn", &serde_json::to_vec(&req)?, 60_000).await?;
    check(reply, &format!("spawn {}", argv.join(" ")))
}

fn check(reply: Vec<u8>, what: &str) -> Result<()> {
    let r: Resp = serde_json::from_slice(&reply)?;
    if r.ok {
        Ok(())
    } else {
        Err(anyhow!("{what}: remote refused: {}", r.error.unwrap_or_default()))
    }
}

fn parse_node_id(s: &str) -> Result<NodeId> {
    let b = hex::decode(s).map_err(|_| anyhow!("node id must be hex"))?;
    b.try_into().map_err(|_| anyhow!("node id must be 32 bytes (64 hex chars)"))
}

fn default_data_dir() -> PathBuf {
    dirs_next::data_dir().unwrap_or_else(|| PathBuf::from(".")).join("ce")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ce_cap::{Resource, authorize};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn id(tag: &str) -> Identity {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("repl-test-{}-{n}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Identity::load_or_generate(&dir).unwrap()
    }

    /// Root cap: org root R -> A, with the given abilities and expiry.
    fn root_cap(root: &Identity, a: NodeId, abilities: &[&str], not_after: u64) -> SignedCapability {
        let caveats = Caveats { not_after, ..Default::default() };
        SignedCapability::issue(root, a, abilities.iter().map(|s| s.to_string()).collect(), Resource::Any, caveats, 1, None)
    }

    fn never() -> impl Fn(&NodeId, u64) -> bool {
        |_, _| false
    }

    #[test]
    fn onward_abilities_is_always_a_subset_and_drops_spawn_at_leaf() {
        let parent = vec!["sync".to_string(), "spawn".to_string(), "tunnel".to_string()];
        // non-leaf keeps sync+spawn, drops the non-replication ability (tunnel)
        let mid = onward_abilities(&parent, true);
        assert!(mid.contains(&"sync".to_string()) && mid.contains(&"spawn".to_string()));
        assert!(!mid.contains(&"tunnel".to_string()));
        // leaf loses spawn
        let leaf = onward_abilities(&parent, false);
        assert!(leaf.contains(&"sync".to_string()));
        assert!(!leaf.contains(&"spawn".to_string()));
        // a parent without spawn can never confer spawn (no escalation)
        let weak = onward_abilities(&["sync".to_string()], true);
        assert!(!weak.contains(&"spawn".to_string()));
    }

    #[test]
    fn attenuate_never_outlives_parent() {
        let now = 1_000;
        // finite parent, long ttl → clamped to parent
        let p = Caveats { not_after: 1_500, ..Default::default() };
        assert_eq!(attenuate(&p, now, 10_000).not_after, 1_500);
        // finite parent, short ttl → child shorter
        assert_eq!(attenuate(&p, now, 100).not_after, 1_100);
        // infinite parent → child still finite
        let inf = Caveats { not_after: 0, ..Default::default() };
        assert_eq!(attenuate(&inf, now, 50).not_after, 1_050);
    }

    #[test]
    fn delegate_produces_a_chain_authorize_accepts() {
        let now = 10_000;
        let root = id("dp-root");
        let a = id("dp-a"); // seed, holds [R->A]
        let b = id("dp-b"); // child
        let host = id("dp-host"); // some node that accepts R as a root
        let chain = vec![root_cap(&root, a.node_id(), &["sync", "spawn"], now + 1000)];
        let onward = delegate(&chain, &a, b.node_id(), true, now, 100, 7).unwrap();
        assert_eq!(onward.len(), 2);
        // B is authorized for both abilities on a host that lists R as a root
        assert!(authorize(&host.node_id(), &[root.node_id()], &[], now, &b.node_id(), "spawn", &onward, &never()).is_ok());
        assert!(authorize(&host.node_id(), &[root.node_id()], &[], now, &b.node_id(), "sync", &onward, &never()).is_ok());
    }

    #[test]
    fn leaf_delegation_cannot_spawn_but_can_sync() {
        let now = 10_000;
        let root = id("leaf-root");
        let a = id("leaf-a");
        let b = id("leaf-b");
        let host = id("leaf-host");
        let chain = vec![root_cap(&root, a.node_id(), &["sync", "spawn"], 0)];
        // child_can_replicate = false → leaf
        let onward = delegate(&chain, &a, b.node_id(), false, now, 100, 7).unwrap();
        assert!(authorize(&host.node_id(), &[root.node_id()], &[], now, &b.node_id(), "sync", &onward, &never()).is_ok());
        assert!(authorize(&host.node_id(), &[root.node_id()], &[], now, &b.node_id(), "spawn", &onward, &never()).is_err());
    }

    #[test]
    fn delegate_refuses_when_signer_is_not_the_holder() {
        let now = 10_000;
        let root = id("nh-root");
        let a = id("nh-a");
        let stranger = id("nh-stranger");
        let b = id("nh-b");
        let chain = vec![root_cap(&root, a.node_id(), &["sync", "spawn"], 0)];
        // stranger is not the audience of [R->A] → cannot delegate
        assert!(delegate(&chain, &stranger, b.node_id(), true, now, 100, 7).is_err());
    }

    #[test]
    fn delegated_expiry_strictly_shrinks_down_the_tree() {
        // Build a 3-level tree R->A->B->C and assert expiry decreases each hop and authorize holds.
        let now = 10_000;
        let root = id("tree-root");
        let a = id("tree-a");
        let b = id("tree-b");
        let c = id("tree-c");
        let host = id("tree-host");
        let l0 = vec![root_cap(&root, a.node_id(), &["sync", "spawn"], now + 10_000)];
        let l1 = delegate(&l0, &a, b.node_id(), true, now, 5_000, 11).unwrap();
        let l2 = delegate(&l1, &b, c.node_id(), false, now, 1_000, 12).unwrap(); // C is a leaf

        let e0 = l0[0].cap.caveats.not_after;
        let e1 = l1.last().unwrap().cap.caveats.not_after;
        let e2 = l2.last().unwrap().cap.caveats.not_after;
        assert!(e2 < e1 && e1 < e0, "expiry must shrink: {e2} < {e1} < {e0}");

        // Each delegatee is authorized on a host rooted at R; the leaf C cannot spawn.
        assert!(authorize(&host.node_id(), &[root.node_id()], &[], now, &b.node_id(), "spawn", &l1, &never()).is_ok());
        assert!(authorize(&host.node_id(), &[root.node_id()], &[], now, &c.node_id(), "sync", &l2, &never()).is_ok());
        assert!(authorize(&host.node_id(), &[root.node_id()], &[], now, &c.node_id(), "spawn", &l2, &never()).is_err());
    }

    #[test]
    fn a_third_party_cannot_use_a_delegated_chain() {
        // The delegated chain names B as audience; an impostor X presenting it is rejected.
        let now = 10_000;
        let root = id("imp-root");
        let a = id("imp-a");
        let b = id("imp-b");
        let x = id("imp-x");
        let host = id("imp-host");
        let chain = vec![root_cap(&root, a.node_id(), &["sync", "spawn"], 0)];
        let onward = delegate(&chain, &a, b.node_id(), true, now, 100, 7).unwrap();
        assert!(authorize(&host.node_id(), &[root.node_id()], &[], now, &x.node_id(), "spawn", &onward, &never()).is_err());
    }

    #[test]
    fn parse_node_id_rules() {
        assert!(parse_node_id(&"a".repeat(64)).is_ok());
        assert!(parse_node_id(&"a".repeat(63)).is_err());
        assert!(parse_node_id("zz").is_err());
    }

    // ---------------------------------------------------------------------
    // Extended suite: attenuation invariants, delegation failure-injection,
    // chain-depth properties, and wire-type serde round-trips.
    // ---------------------------------------------------------------------

    /// Property: `onward_abilities` output is ALWAYS a subset of the parent's abilities
    /// intersected with the replication set — it can never introduce a new ability.
    #[test]
    fn onward_abilities_never_introduces_new_powers() {
        let cases: &[&[&str]] = &[
            &[],
            &["sync"],
            &["spawn"],
            &["sync", "spawn"],
            &["tunnel", "exec"],                  // none replicable
            &["sync", "spawn", "tunnel", "exec"], // mixed
            &["spawn", "spawn"],                  // duplicate parent ability
        ];
        for parent in cases {
            let parent: Vec<String> = parent.iter().map(|s| s.to_string()).collect();
            for replicate in [true, false] {
                let child = onward_abilities(&parent, replicate);
                for ability in &child {
                    assert!(
                        parent.contains(ability),
                        "introduced {ability:?} not held by parent {parent:?}"
                    );
                    assert!(
                        REPLICATION_ABILITIES.contains(&ability.as_str()),
                        "non-replication ability {ability:?} leaked through"
                    );
                    if !replicate {
                        assert_ne!(ability, "spawn", "leaf must never carry spawn");
                    }
                }
            }
        }
    }

    #[test]
    fn onward_abilities_empty_parent_yields_nothing() {
        assert!(onward_abilities(&[], true).is_empty());
        assert!(onward_abilities(&[], false).is_empty());
    }

    #[test]
    fn onward_abilities_only_non_replicable_yields_nothing() {
        let parent = vec!["tunnel".to_string(), "exec".to_string()];
        assert!(onward_abilities(&parent, true).is_empty());
        assert!(onward_abilities(&parent, false).is_empty());
    }

    /// Property: for any (now, ttl) and any parent caveats, the attenuated expiry is
    /// `narrower_or_equal`: it never exceeds the parent (when the parent is finite) and
    /// is always finite for the child.
    #[test]
    fn attenuate_expiry_is_monotone_narrowing() {
        let now = 1_000u64;
        for parent_exp in [0u64, 1, 999, 1_000, 1_001, 5_000, u64::MAX] {
            for ttl in [0u64, 1, 500, 100_000, u64::MAX] {
                let p = Caveats { not_after: parent_exp, ..Default::default() };
                let child = attenuate(&p, now, ttl);
                // child is always finite
                assert_ne!(child.not_after, 0, "child must get a finite expiry");
                if parent_exp != 0 {
                    assert!(
                        child.not_after <= parent_exp,
                        "child {} outlives parent {} (ttl={ttl})",
                        child.not_after,
                        parent_exp
                    );
                }
                // child never exceeds now+ttl (saturating)
                assert!(child.not_after <= now.saturating_add(ttl));
            }
        }
    }

    #[test]
    fn attenuate_ttl_overflow_saturates_not_panics() {
        // now+ttl overflows u64 → saturating_add prevents wrap; infinite parent takes it.
        let inf = Caveats { not_after: 0, ..Default::default() };
        let c = attenuate(&inf, u64::MAX, u64::MAX);
        assert_eq!(c.not_after, u64::MAX);
    }

    #[test]
    fn attenuate_preserves_other_caveats() {
        // Only not_after changes; the rest of the parent's caveats are inherited verbatim.
        let p = Caveats { not_after: 5_000, ..Default::default() };
        let c = attenuate(&p, 1_000, 100);
        let mut expected = p.clone();
        expected.not_after = 1_100;
        assert_eq!(c, expected);
    }

    #[test]
    fn delegate_empty_chain_is_rejected() {
        let a = id("ec-a");
        let b = id("ec-b");
        assert!(delegate(&[], &a, b.node_id(), true, 10_000, 100, 7).is_err());
    }

    #[test]
    fn delegate_with_no_replicable_abilities_is_rejected() {
        // Parent holds only non-replicable abilities → nothing to delegate.
        let now = 10_000;
        let root = id("nr-root");
        let a = id("nr-a");
        let b = id("nr-b");
        let chain = vec![root_cap(&root, a.node_id(), &["tunnel", "exec"], 0)];
        assert!(delegate(&chain, &a, b.node_id(), true, now, 100, 7).is_err());
    }

    #[test]
    fn delegate_sync_only_parent_makes_sync_leaf_even_when_replicating() {
        // A parent that only holds `sync` cannot confer `spawn`, so even a "replicating"
        // child gets sync only — it is structurally a leaf.
        let now = 10_000;
        let root = id("so-root");
        let a = id("so-a");
        let b = id("so-b");
        let host = id("so-host");
        let chain = vec![root_cap(&root, a.node_id(), &["sync"], 0)];
        let onward = delegate(&chain, &a, b.node_id(), true, now, 100, 7).unwrap();
        let leaf = onward.last().unwrap();
        assert_eq!(leaf.cap.abilities, vec!["sync".to_string()]);
        assert!(authorize(&host.node_id(), &[root.node_id()], &[], now, &b.node_id(), "sync", &onward, &never()).is_ok());
        assert!(authorize(&host.node_id(), &[root.node_id()], &[], now, &b.node_id(), "spawn", &onward, &never()).is_err());
    }

    #[test]
    fn delegate_chain_grows_by_exactly_one_each_hop() {
        let now = 10_000;
        let root = id("len-root");
        let a = id("len-a");
        let b = id("len-b");
        let c = id("len-c");
        let l0 = vec![root_cap(&root, a.node_id(), &["sync", "spawn"], 0)];
        let l1 = delegate(&l0, &a, b.node_id(), true, now, 1000, 1).unwrap();
        let l2 = delegate(&l1, &b, c.node_id(), true, now, 1000, 2).unwrap();
        assert_eq!(l0.len(), 1);
        assert_eq!(l1.len(), 2);
        assert_eq!(l2.len(), 3);
        // parent prefix is preserved unchanged (compared by stable cap id)
        let ids = |chain: &[SignedCapability]| chain.iter().map(|c| c.id()).collect::<Vec<_>>();
        assert_eq!(ids(&l2)[..2], ids(&l1)[..]);
        assert_eq!(ids(&l1)[..1], ids(&l0)[..]);
    }

    #[test]
    fn delegate_each_child_cap_links_to_its_parent() {
        let now = 10_000;
        let root = id("link-root");
        let a = id("link-a");
        let b = id("link-b");
        let l0 = vec![root_cap(&root, a.node_id(), &["sync", "spawn"], 0)];
        let l1 = delegate(&l0, &a, b.node_id(), true, now, 1000, 1).unwrap();
        let parent = &l0[0];
        let child = l1.last().unwrap();
        assert_eq!(child.cap.parent, Some(parent.id()), "child must reference parent id");
        assert_eq!(child.cap.audience, b.node_id());
    }

    #[test]
    fn authorize_rejects_expired_delegated_cap() {
        // A cap valid at issue time must be refused once the clock passes its expiry.
        let now = 10_000;
        let root = id("exp-root");
        let a = id("exp-a");
        let b = id("exp-b");
        let host = id("exp-host");
        let chain = vec![root_cap(&root, a.node_id(), &["sync", "spawn"], now + 10_000)];
        let onward = delegate(&chain, &a, b.node_id(), true, now, 100, 7).unwrap();
        // valid now
        assert!(authorize(&host.node_id(), &[root.node_id()], &[], now, &b.node_id(), "sync", &onward, &never()).is_ok());
        // expired after now+100
        let later = now + 101;
        assert!(authorize(&host.node_id(), &[root.node_id()], &[], later, &b.node_id(), "sync", &onward, &never()).is_err());
    }

    #[test]
    fn authorize_rejects_unrooted_chain() {
        // Host that does NOT list R as a root rejects the chain even if every link is valid.
        let now = 10_000;
        let root = id("ur-root");
        let other_root = id("ur-other");
        let a = id("ur-a");
        let b = id("ur-b");
        let host = id("ur-host");
        let chain = vec![root_cap(&root, a.node_id(), &["sync", "spawn"], 0)];
        let onward = delegate(&chain, &a, b.node_id(), true, now, 100, 7).unwrap();
        // host trusts only `other_root`
        assert!(authorize(&host.node_id(), &[other_root.node_id()], &[], now, &b.node_id(), "sync", &onward, &never()).is_err());
    }

    #[test]
    fn authorize_honors_revocation_predicate() {
        // Revocation is keyed by (issuer, nonce). The child link is issued by `a` with nonce 7;
        // revoking that (issuer, nonce) pair must make authorize fail.
        let now = 10_000;
        let root = id("rv-root");
        let a = id("rv-a");
        let b = id("rv-b");
        let host = id("rv-host");
        let chain = vec![root_cap(&root, a.node_id(), &["sync", "spawn"], 0)];
        let onward = delegate(&chain, &a, b.node_id(), true, now, 100, 7).unwrap();
        let revoked_issuer = a.node_id();
        let revoked = move |issuer: &NodeId, nonce: u64| *issuer == revoked_issuer && nonce == 7;
        assert!(authorize(&host.node_id(), &[root.node_id()], &[], now, &b.node_id(), "sync", &onward, &revoked).is_err());
        // with no revocation it remains valid
        assert!(authorize(&host.node_id(), &[root.node_id()], &[], now, &b.node_id(), "sync", &onward, &never()).is_ok());
    }

    #[test]
    fn parse_node_id_roundtrips_through_hex() {
        let raw = [7u8; 32];
        let hexed = hex::encode(raw);
        let parsed = parse_node_id(&hexed).unwrap();
        assert_eq!(parsed.as_ref(), &raw[..]);
    }

    #[test]
    fn parse_node_id_rejects_too_long_and_empty() {
        assert!(parse_node_id("").is_err());
        assert!(parse_node_id(&"a".repeat(66)).is_err()); // 33 bytes
        assert!(parse_node_id(&"a".repeat(65)).is_err()); // odd hex length
    }

    // ---- wire types (Req/Resp/check) ----

    #[test]
    fn req_serializes_with_defaulted_optional_fields() {
        let req = Req { caps: "tok".into(), path: "x/y".into(), data_hex: Some("dead".into()), ..Default::default() };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(v["caps"], "tok");
        assert_eq!(v["path"], "x/y");
        assert_eq!(v["data_hex"], "dead");
    }

    #[test]
    fn resp_deserializes_tolerantly() {
        let ok: Resp = serde_json::from_str(r#"{"ok":true}"#).unwrap();
        assert!(ok.ok && ok.error.is_none());
        let err: Resp = serde_json::from_str(r#"{"ok":false,"error":"nope"}"#).unwrap();
        assert!(!err.ok);
        assert_eq!(err.error.as_deref(), Some("nope"));
    }

    #[test]
    fn check_maps_ok_and_error_replies() {
        let ok = serde_json::to_vec(&Resp { ok: true, ..Default::default() }).unwrap();
        assert!(check(ok, "sync foo").is_ok());
        let bad = serde_json::to_vec(&Resp { ok: false, error: Some("denied".into()), ..Default::default() }).unwrap();
        let e = check(bad, "sync foo").unwrap_err();
        assert!(e.to_string().contains("denied"));
        // malformed reply → parse error, not a panic
        assert!(check(b"not json".to_vec(), "sync foo").is_err());
    }
}
