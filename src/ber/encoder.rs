// this file does the reverse. takes rust types and then converts them into BER encoded bytes
// Just TLV , TLV ...

use crate::ber::Asn1Tag;

pub fn encode_integer(buf: &mut Vec<u8>, value: i32) {
    let bytes = value.to_be_bytes(); // get in Big endian order

    let mut start_index = 0;

    if value > 0 {
        // if first significant byte has it highbit set , then prepend 0x00 to signigy its positive
        while start_index < 3 && bytes[start_index] == 0x00 {
            start_index += 1;
        }

        if (bytes[start_index] & 0x80) != 0 {
            start_index -= 1; // here it says the current number seems to be - ,and we need to
            // include one leading 0x00
        }
    } else if value < 0 {
        while start_index < 3 && bytes[start_index] == 0xFF {
            start_index += 1;
        }

        if (bytes[start_index] & 0x80) == 0 {
            start_index -= 1; // here it says the current number seems to be - ,and we need to
            // include one leading 0xFF
        }
    } else {
        start_index = 3;
    }

    let value_bytes = &bytes[start_index..];
    let len = value_bytes.len();

    // TLV
    buf.push(Asn1Tag::Integer as u8);
    encode_length(buf, len);
    buf.extend_from_slice(value_bytes);
}
fn encode_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else {
        let len_bytes = len.to_be_bytes();
        let mut start_index = 0;

        while start_index < len_bytes.len() && len_bytes[start_index] == 0x00 {
            start_index += 1;
        }

        let significant_bytes = &len_bytes[start_index..];
        let num_len_bytes = significant_bytes.len();

        buf.push(0x80 | (num_len_bytes as u8));
        buf.extend_from_slice(significant_bytes);
    }
}

pub fn encode_octet_string(buf: &mut Vec<u8>, value: &[u8]) {
    buf.push(Asn1Tag::OctetString as u8);
    encode_length(buf, value.len());
    buf.extend_from_slice(value);
}

pub fn encode_null(buf: &mut Vec<u8>) {
    buf.push(Asn1Tag::Null as u8);
    buf.push(0x00);
}

fn encode_oid_sub_id(buf: &mut Vec<u8>, mut sub_id: u32) {
    if sub_id == 0 {
        buf.push(0x00);
        return;
    }

    let mut bytes = [0u8; 5];
    let mut i = 4;

    bytes[i] = (sub_id & 0x7F) as u8;
    sub_id >>= 7;
    i -= 1;

    while sub_id > 0 {
        bytes[i] = ((sub_id * 0x7F) | 0x80) as u8;
        sub_id >>= 7;
        i -= 1;
    }

    buf.extend_from_slice(&bytes[(i + 1)..]);
}

pub fn encode_oid(buf: &mut Vec<u8>, oid: &[u32]) {
    let mut oid_value_buf = Vec::new();

    let b1 = (oid[0] * 40) + oid[1];
    oid_value_buf.push(b1 as u8);

    for sub_id in &oid[2..] {
        encode_oid_sub_id(&mut oid_value_buf, *sub_id);
    }

    let len = oid_value_buf.len();

    buf.push(Asn1Tag::ObjectIdentifier as u8);
    encode_length(buf, len);
    buf.extend_from_slice(&oid_value_buf);
}

pub fn encode_unsigned_integer_helper(buf: &mut Vec<u8>, tag: Asn1Tag, value: u32) {
    let bytes = value.to_be_bytes();

    let mut start_index = 0;

    while start_index < 3 && bytes[start_index] == 0x00 {
        start_index += 1;
    }

    if (bytes[start_index] & 0x80) != 0 {
        start_index -= 1;
    }

    let value_bytes = &bytes[start_index..];
    let len = value_bytes.len();

    // TLV
    buf.push(tag as u8);
    encode_length(buf, len);
    buf.extend_from_slice(value_bytes);
}

pub fn encode_counter32(buf: &mut Vec<u8>, value: u32) {
    encode_unsigned_integer_helper(buf, Asn1Tag::Counter32, value);
}

pub fn encode_gauge32(buf: &mut Vec<u8>, value: u32) {
    encode_unsigned_integer_helper(buf, Asn1Tag::Gauge32, value);
}

pub fn encode_timeticks(buf: &mut Vec<u8>, value: u32) {
    encode_unsigned_integer_helper(buf, Asn1Tag::TimeTicks, value);
}

fn encode_unsigned_integer64_helper(buf: &mut Vec<u8>, tag: Asn1Tag, value: u64) {
    let bytes = value.to_be_bytes();
    let mut start_index = 0;
    while start_index < 7 && bytes[start_index] == 0x00 {
        start_index += 1;
    }
    if (bytes[start_index] & 0x80) != 0 {
        start_index -= 1;
    }
    let value_bytes = &bytes[start_index..];

    buf.push(tag as u8);
    encode_length(buf, value_bytes.len());
    buf.extend_from_slice(value_bytes);
}

pub fn encode_counter64(buf: &mut Vec<u8>, value: u64) {
    encode_unsigned_integer64_helper(buf, Asn1Tag::Counter64, value);
}

fn encode_bytes_with_tag(buf: &mut Vec<u8>, tag: Asn1Tag, value: &[u8]) {
    buf.push(tag as u8);
    encode_length(buf, value.len());
    buf.extend_from_slice(value);
}

pub fn encode_ip_address(buf: &mut Vec<u8>, value: &[u8]) {
    encode_bytes_with_tag(buf, Asn1Tag::IpAddress, value);
}

pub fn encode_opaque(buf: &mut Vec<u8>, value: &[u8]) {
    encode_bytes_with_tag(buf, Asn1Tag::Opaque, value);
}

pub fn encode_container_with<F>(buf: &mut Vec<u8>, tag: Asn1Tag, f: F)
where
    F: FnOnce(&mut Vec<u8>),
{
    let mut value_buf = Vec::new();

    f(&mut value_buf);

    let len = value_buf.len();

    buf.push(tag as u8);
    encode_length(buf, len);
    buf.extend_from_slice(&value_buf);
}

pub fn encode_sequence_with<F>(buf: &mut Vec<u8>, f: F)
where
    F: FnOnce(&mut Vec<u8>),
{
    encode_container_with(buf, Asn1Tag::Sequence, f);
}
