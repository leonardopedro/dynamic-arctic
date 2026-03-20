use crate::types::{AggregateKey, PartialSignature};
use crate::arctic::{ArcticNode, aggregate_signatures};
use std::time::Duration;
use tokio::time::timeout;
use std::collections::HashSet;

pub struct RoastCoordinator {
    pub aggregate_key: AggregateKey,
    nodes: Vec<ArcticNode>, 
}

impl RoastCoordinator {
    pub fn new(aggregate_key: AggregateKey, nodes: Vec<ArcticNode>) -> Self {
        Self { aggregate_key, nodes }
    }

    pub async fn sign_robustly(&self, message: &[u8]) -> Result<ed25519_dalek::Signature, String> {
        let mut blacklisted = HashSet::new();
        let t = self.aggregate_key.threshold;

        loop {
            let active_nodes: Vec<&ArcticNode> = self.nodes.iter()
                .filter(|n| !blacklisted.contains(&n.node_id))
                .take(t).collect();

            if active_nodes.len() < t {
                return Err("CRITICAL: Network partitioned. Cannot reach threshold.".into());
            }

            let mut tasks = vec![];
            for node in active_nodes {
                let msg = message.to_vec();
                tasks.push((node.node_id, async move { node.sign_partial(&msg).await }));
            }

            let mut valid_shares = vec![];
            let mut round_failed = false;

            for (id, task) in tasks {
                match timeout(Duration::from_millis(800), task).await {
                    Ok(Ok(share)) => valid_shares.push(share),
                    Ok(Err(e)) => {
                        println!("Node {} failed: {}. ROAST blacklisting...", id, e);
                        blacklisted.insert(id);
                        round_failed = true;
                        break;
                    }
                    Err(_) => {
                        println!("Node {} timed out. ROAST blacklisting...", id);
                        blacklisted.insert(id);
                        round_failed = true;
                        break;
                    }
                }
            }

            if !round_failed && valid_shares.len() >= t {
                return aggregate_signatures(message, &valid_shares, t);
            }
            // Loop restarts instantly on failure.
        }
    }
}
