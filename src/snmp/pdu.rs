use crate::ber::decoder::{decode_unsigned_integer, decode_unsigned_integer64};
use crate::ber::encoder;
use crate::ber::{Asn1Tag, BerError, parse_ber_object};
use crate::ber::{BerObject, BerResult, decode_oid, decoder::decode_integer};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarBind {
    pub oid: Vec<u32>,
    pub value: ObjectSyntax,
}

impl VarBind {
    pub fn write_to_buf(&self, buf: &mut Vec<u8>) {
        encoder::encode_sequence_with(buf, |content_buf| {
            encoder::encode_oid(content_buf, &self.oid);
            self.value.write_to_buf(content_buf);
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectSyntax {
    Integer(i32),
    OctetString(Vec<u8>),
    Null,
    ObjectIdentifier(Vec<u32>),
    IpAddress(Vec<u8>),
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32),
    Opaque(Vec<u8>),
    Counter64(u64),
}

impl ObjectSyntax {
    pub fn from_ber(obj: BerObject) -> BerResult<Self> {
        match obj.tag {
            crate::ber::Asn1Tag::Integer => {
                let val = decode_integer(obj.value)?;
                Ok(ObjectSyntax::Integer(val))
            }
            Asn1Tag::OctetString => Ok(ObjectSyntax::OctetString(obj.value.to_vec())),
            Asn1Tag::Null => Ok(ObjectSyntax::Null),
            Asn1Tag::ObjectIdentifier => {
                let oid = decode_oid(obj.value)?;
                Ok(ObjectSyntax::ObjectIdentifier(oid))
            }
            Asn1Tag::IpAddress => {
                // An IpAddress is just an OctetString
                Ok(ObjectSyntax::IpAddress(obj.value.to_vec()))
            }
            Asn1Tag::Counter32 => {
                let val = decode_unsigned_integer(obj.value)?;
                Ok(ObjectSyntax::Counter32(val))
            }
            Asn1Tag::Gauge32 => {
                let val = decode_unsigned_integer(obj.value)?;
                Ok(ObjectSyntax::Gauge32(val))
            }
            Asn1Tag::TimeTicks => {
                let val = decode_unsigned_integer(obj.value)?;
                Ok(ObjectSyntax::TimeTicks(val))
            }
            Asn1Tag::Opaque => {
                // Opaque is also just an OctetString
                Ok(ObjectSyntax::Opaque(obj.value.to_vec()))
            }
            Asn1Tag::Counter64 => {
                let val = decode_unsigned_integer64(obj.value)?;
                Ok(ObjectSyntax::Counter64(val))
            }
            _ => Err(BerError::UnsupportedType(obj.tag as u8)),
        }
    }

    // for encoder
    pub fn write_to_buf(&self, buf: &mut Vec<u8>) {
        match self {
            ObjectSyntax::Integer(val) => encoder::encode_integer(buf, *val),
            ObjectSyntax::OctetString(val) => encoder::encode_octet_string(buf, val),
            ObjectSyntax::Null => encoder::encode_null(buf),
            ObjectSyntax::ObjectIdentifier(val) => encoder::encode_oid(buf, val),
            ObjectSyntax::IpAddress(val) => encoder::encode_ip_address(buf, val),
            ObjectSyntax::Counter32(val) => encoder::encode_counter32(buf, *val),
            ObjectSyntax::Gauge32(val) => encoder::encode_gauge32(buf, *val),
            ObjectSyntax::TimeTicks(val) => encoder::encode_timeticks(buf, *val),
            ObjectSyntax::Opaque(val) => encoder::encode_opaque(buf, val),
            ObjectSyntax::Counter64(val) => encoder::encode_counter64(buf, *val),
        }
    }
}

pub fn parse_varbind(obj: BerObject) -> BerResult<VarBind> {
    if obj.tag != Asn1Tag::Sequence {
        return Err(BerError::UnexpectedTag {
            expected: Asn1Tag::Sequence,
            got: obj.tag,
        });
    }

    let (oid_obj, rest_after_oid) = parse_ber_object(obj.value)?;

    if oid_obj.tag != Asn1Tag::ObjectIdentifier {
        return Err(BerError::UnexpectedTag {
            expected: Asn1Tag::ObjectIdentifier,
            got: obj.tag,
        });
    }

    let oid = decode_oid(oid_obj.value)?;
    let (value_obj, rest) = parse_ber_object(rest_after_oid)?;

    if !rest.is_empty() {
        return Err(BerError::TrailingData);
    }

    let value = ObjectSyntax::from_ber(value_obj)?;

    Ok(VarBind { oid, value })
}

pub fn parse_varbind_list(obj: BerObject) -> BerResult<Vec<VarBind>> {
    if obj.tag != Asn1Tag::Sequence {
        return Err(BerError::UnexpectedTag {
            expected: Asn1Tag::Sequence,
            got: obj.tag,
        });
    }

    let mut varbinds = Vec::new();

    let mut current_slice = obj.value;

    while !current_slice.is_empty() {
        let (varbind_object, rest) = parse_ber_object(current_slice)?;

        let varbind = parse_varbind(varbind_object)?;
        varbinds.push(varbind);

        current_slice = rest;
    }

    Ok(varbinds)
}

// https://datatracker.ietf.org/doc/html/rfc1157#section-4.1.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ErrorStatus {
    NoError = 0,
    TooBig = 1,
    NoSuchName = 2,
    BadValue = 3,
    ReadOnly = 4,
    GenErr = 5,
}

impl TryFrom<i32> for ErrorStatus {
    type Error = BerError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ErrorStatus::NoError),
            1 => Ok(ErrorStatus::TooBig),
            2 => Ok(ErrorStatus::NoSuchName),
            3 => Ok(ErrorStatus::BadValue),
            4 => Ok(ErrorStatus::ReadOnly),
            5 => Ok(ErrorStatus::GenErr),
            _ => Err(BerError::InvalidEnumValue(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdu {
    pub tag: Asn1Tag,
    pub request_id: i32,
    pub error_status: ErrorStatus,
    pub error_index: i32,
    pub varbinds: Vec<VarBind>,
}

impl Pdu {
    pub fn write_to_buf(&self, buf: &mut Vec<u8>) {
        encoder::encode_container_with(buf, self.tag, |content_buf| {
            encoder::encode_integer(content_buf, self.request_id);
            encoder::encode_integer(content_buf, self.error_status as i32);
            encoder::encode_integer(content_buf, self.error_index);
            encoder::encode_sequence_with(content_buf, |varbind_list_buf| {
                for varbind in &self.varbinds {
                    varbind.write_to_buf(varbind_list_buf);
                }
            });
        });
    }
}

pub fn parse_pdu(obj: BerObject) -> BerResult<Pdu> {
    let pdu_tag = obj.tag;

    let mut current_slice = obj.value;

    let (req_id_obj, rest) = parse_ber_object(current_slice)?;
    if req_id_obj.tag != Asn1Tag::Integer {
        return Err(BerError::UnexpectedTag {
            expected: Asn1Tag::Integer,
            got: req_id_obj.tag,
        });
    }

    let request_id = decode_integer(req_id_obj.value)?;
    current_slice = rest;

    let (err_stat_obj, rest) = parse_ber_object(current_slice)?;
    if err_stat_obj.tag != Asn1Tag::Integer {
        return Err(BerError::UnexpectedTag {
            expected: Asn1Tag::Integer,
            got: err_stat_obj.tag,
        });
    }
    let error_status_raw = decode_integer(err_stat_obj.value)?;
    let error_status = ErrorStatus::try_from(error_status_raw)?;
    current_slice = rest;

    let (err_idx_obj, rest) = parse_ber_object(current_slice)?;
    if err_idx_obj.tag != Asn1Tag::Integer {
        return Err(BerError::UnexpectedTag {
            expected: Asn1Tag::Integer,
            got: err_idx_obj.tag,
        });
    }
    let error_index = decode_integer(err_idx_obj.value)?;
    current_slice = rest;

    let (varbind_list_obj, rest) = parse_ber_object(current_slice)?;
    let varbinds = parse_varbind_list(varbind_list_obj)?;
    current_slice = rest;

    if !current_slice.is_empty() {
        return Err(BerError::TrailingData);
    }

    Ok(Pdu {
        tag: pdu_tag,
        request_id,
        error_status,
        error_index,
        varbinds,
    })
}
