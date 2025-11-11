use crate::{
    ber::{Asn1Tag, BerError, BerResult, decoder::decode_integer, parse_ber_object},
    snmp::pdu::{Pdu, parse_pdu},
};

#[derive(Debug, Clone, PartialEq)]
pub struct SnmpMessage {
    pub version: i32,
    pub community: Vec<u8>,
    pub pdu: Pdu,
}

pub fn parse_message(inpt: &[u8]) -> BerResult<SnmpMessage> {
    let (msgobj, rest) = parse_ber_object(inpt)?;

    if msgobj.tag != Asn1Tag::Sequence {
        return Err(BerError::UnexpectedTag {
            expected: Asn1Tag::Sequence,
            got: msgobj.tag,
        });
    }

    if !rest.is_empty() {
        return Err(BerError::TrailingData);
    }

    let mut current_slice = msgobj.value;

    // version
    let (ver_obj, rest) = parse_ber_object(current_slice)?;
    if ver_obj.tag != Asn1Tag::Integer {
        return Err(BerError::UnexpectedTag {
            expected: Asn1Tag::Integer,
            got: ver_obj.tag,
        });
    }
    let version = decode_integer(ver_obj.value)?;
    current_slice = rest;

    // Pare community
    let (comm, rest) = parse_ber_object(current_slice)?;
    if comm.tag != Asn1Tag::OctetString {
        return Err(BerError::UnexpectedTag {
            expected: Asn1Tag::OctetString,
            got: comm.tag,
        });
    }

    let community = comm.value.to_vec();
    current_slice = rest;

    let (pdu_object, rest) = parse_ber_object(current_slice)?;
    let pdu = parse_pdu(pdu_object)?;
    current_slice = rest;

    // at this point there should be nothing
    if !current_slice.is_empty() {
        return Err(BerError::TrailingData);
    }

    Ok(SnmpMessage {
        version,
        community,
        pdu,
    })
}
