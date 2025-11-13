use crate::ber::Asn1Tag;
use crate::snmp::message::{SnmpMessage, parse_message};
use crate::snmp::pdu::{ErrorStatus, ObjectSyntax, Pdu, VarBind};
use anyhow::anyhow;

use anyhow::Context;
pub mod network;
use anyhow::Result;

fn parse_oid_string(oid_str: &str) -> Result<Vec<u32>> {
    oid_str
        .split('.')
        .filter(|s| !s.is_empty()) // Filter out the empty string before the first dot
        .map(|s| {
            s.parse::<u32>()
                .with_context(|| format!("Invalid OID component: '{}'", s))
        })
        .collect::<Result<Vec<u32>, _>>()
}

/// The main SNMP Manager struct.
/// This will be the entry point for all operations.
pub struct Manager {}

// just cause rust analyzer wouldnt leave me
impl Default for Manager {
    fn default() -> Self {
        Self::new()
    }
}

impl Manager {
    /// Creates a new Manager.
    pub fn new() -> Self {
        Self {}
    }

    /// Performs a single, asynchronous SNMP GET operation.
    pub async fn get(&self, target: &str, community: &str, oid_str: &str) -> Result<VarBind> {
        let oid = parse_oid_string(oid_str)?;

        // Build the GetRequest packet from scratch.
        let message = SnmpMessage {
            version: 1, // 1 = v2c
            community: community.as_bytes().to_vec(),
            pdu: Pdu {
                tag: Asn1Tag::GetRequest,
                request_id: 1, // Simple request ID
                error_status: ErrorStatus::NoError,
                error_index: 0,
                varbinds: vec![VarBind {
                    oid,
                    value: ObjectSyntax::Null, // Value is Null for a GetRequest
                }],
            },
        };
        let packet_bytes = message.to_bytes();

        // Send and receive the raw bytes, handling timeouts.
        let response_bytes = network::send_and_receive(target, &packet_bytes).await?;

        // Parse the raw response bytes into our structs.
        let response_message = parse_message(&response_bytes)
            .map_err(|e| anyhow!("Failed to parse response: {}", e))?;

        if response_message.pdu.error_status != ErrorStatus::NoError {
            return Err(anyhow!(
                "SNMP Error: {:?} (Index: {})",
                response_message.pdu.error_status,
                response_message.pdu.error_index
            ));
        }

        response_message
            .pdu
            .varbinds
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("No VarBinds in response"))
    }
}
