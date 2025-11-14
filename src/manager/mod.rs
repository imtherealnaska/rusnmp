use crate::ber::Asn1Tag;
use crate::snmp::message::{SnmpMessage, parse_message};
use crate::snmp::pdu::{ErrorStatus, ObjectSyntax, Pdu, PduData, VarBind};
use anyhow::{Ok, anyhow};

use anyhow::Context;
pub mod network;
use anyhow::Result;
use tokio::net::lookup_host;

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

fn is_in_subtree(root: &[u32], child: &[u32]) -> bool {
    if child.len() < root.len() {
        return false;
    }
    child.starts_with(root)
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
                data: PduData::Basic {
                    error_status: ErrorStatus::NoError,
                    error_index: 0,
                },
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

        if let PduData::Basic {
            error_status,
            error_index,
        } = response_message.pdu.data
        {
            if error_status != ErrorStatus::NoError {
                return Err(anyhow!(
                    "SNMP Error: {:?} (Index: {})",
                    error_status,
                    error_index
                ));
            }
        }

        response_message
            .pdu
            .varbinds
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("No VarBinds in response"))
    }

    pub async fn walk(
        &self,
        target: &str,
        community: &str,
        root_id_str: &str,
    ) -> Result<Vec<VarBind>> {
        let mut results = Vec::new();
        let root_id = parse_oid_string(root_id_str)?;
        let mut current_oid = root_id.clone();

        loop {
            let message = SnmpMessage {
                version: 1,
                community: community.as_bytes().to_vec(),
                pdu: Pdu {
                    tag: Asn1Tag::GetNextRequest,
                    request_id: 1,
                    data: PduData::Basic {
                        error_status: ErrorStatus::NoError,
                        error_index: 0,
                    },
                    varbinds: vec![VarBind {
                        oid: current_oid.clone(),
                        value: ObjectSyntax::Null,
                    }],
                },
            };

            let packet_bytes = message.to_bytes();

            let response_bytes = network::send_and_receive(target, &packet_bytes).await?;

            let response_message = parse_message(&response_bytes)
                .map_err(|e| anyhow!("Failed to parse response: {}", e))?;

            // check for errors in the response
            if let PduData::Basic {
                error_status,
                error_index,
            } = response_message.pdu.data
            {
                if error_status != ErrorStatus::NoError {
                    if error_status == ErrorStatus::NoSuchName {
                        break;
                    }

                    return Err(anyhow!(
                        "
                SNMP Error: {:?} (Index : {}) ,
                        ",
                        error_status,
                        error_index
                    ));
                }
            }

            let response_varbind = response_message
                .pdu
                .varbinds
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("No Varbinds in getnext response"))?;

            match response_varbind.value {
                ObjectSyntax::NoSuchObject
                | ObjectSyntax::NoSuchInstance
                | ObjectSyntax::EndOfMib => {
                    break;
                }
                _ => {}
            }

            if !is_in_subtree(&root_id, &response_varbind.oid) {
                break;
            }

            current_oid = response_varbind.oid.clone();
            results.push(response_varbind);
        }
        Ok(results)
    }

    pub async fn get_bulk(
        &self,
        target: &str,
        community: &str,
        non_repeaters: i32,
        max_repititions: i32,
        oid_strs: &[&str],
    ) -> Result<Vec<VarBind>> {
        let mut request_varbinds = Vec::new();
        for s in oid_strs {
            let oid = parse_oid_string(s)?;
            request_varbinds.push(VarBind {
                oid,
                value: ObjectSyntax::Null, // null for request
            });
        }

        if request_varbinds.is_empty() {
            return Err(anyhow!("GetBulkRequest needs atlaeat one oid"));
        }

        // encode
        let message = SnmpMessage {
            version: 1,
            community: community.as_bytes().to_vec(),
            pdu: Pdu {
                tag: Asn1Tag::GetBulkRequest,
                request_id: 1,
                data: crate::snmp::pdu::PduData::Bulk {
                    non_repeaters,
                    max_repititions,
                },
                varbinds: request_varbinds,
            },
        };

        let packet_bytes = message.to_bytes();
        let response_bytes = network::send_and_receive(target, &packet_bytes).await?;

        let response_message = parse_message(&response_bytes)
            .map_err(|e| anyhow!("Faield to parse response: {}", e))?;

        if response_message.pdu.tag != Asn1Tag::GetResponse {
            return Err(anyhow!(
                "Expewcted GetBulkRequest, got {:?}",
                response_message.pdu.tag
            ));
        }

        match response_message.pdu.data {
            PduData::Basic {
                error_status,
                error_index,
            } => {
                if error_status != ErrorStatus::NoError {
                    return Err(anyhow!(
                        "
                    SNMP Error : {:?} (Index : {})
                            ",
                        error_status,
                        error_index
                    ));
                }
            }
            PduData::Bulk { .. } => {
                return Err(anyhow!("received unexpected GetBulk PDU in response"));
            }
        }

        Ok(response_message.pdu.varbinds)
    }

    pub async fn bulk_walk(
        &self,
        target: &str,
        community: &str,
        root_oid_str: &str,
        max_repititions: i32,
    ) -> Result<Vec<VarBind>> {
        let mut results = Vec::new();
        let root_oid = parse_oid_string(root_oid_str)?;
        let mut current_oid_str = root_oid_str.to_string();

        loop {
            // call existing get_bulk function
            let varbind_batch = self
                .get_bulk(target, community, 0, max_repititions, &[&current_oid_str])
                .await?;

            if varbind_batch.is_empty() {
                break;
            }

            let mut last_oid_in_batch = None;
            for varbind in varbind_batch {
                match varbind.value {
                    ObjectSyntax::EndOfMib
                    | ObjectSyntax::NoSuchObject
                    | ObjectSyntax::NoSuchInstance => {
                        return Ok(results);
                    }
                    _ => {}
                }

                if !is_in_subtree(&root_oid, &varbind.oid) {
                    return Ok(results);
                }

                last_oid_in_batch = Some(varbind.oid.clone());
                results.push(varbind);
            }

            if let Some(last_oid) = last_oid_in_batch {
                current_oid_str = last_oid
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(".");
            } else {
                // if we get a batch then this should not be reached... safe exit
                break;
            }
        }
        Ok(results)
    }
}
