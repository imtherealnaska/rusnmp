use thiserror::Error;

pub mod decoder;
pub mod encoder;

pub type BerResult<T> = Result<T, BerError>;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum BerError {
    #[error("Incomplete data: not enough bytes")]
    IncompleteData,

    #[error("Malformed length field")]
    MalformedLength,

    #[error("Malformed tag")]
    MalformedTag,

    #[error("Unexpected End of data")]
    UnexpectedEof,

    #[error("Unsupported ASN.1 type tag: {0:02X}")]
    UnsupportedType(u8),

    #[error("Integer Overfloe")]
    IntegerOverflow,

    #[error("Unexpected ASN.1 Tag: expected {expected:?}, got {got:?}")]
    UnexpectedTag { expected: Asn1Tag, got: Asn1Tag },

    #[error("Trailing data after parsing complete structure")]
    TrailingData,

    #[error("Invalid value for enum: {0}")]
    InvalidEnumValue(i32),
}

/// ┌─────────────────────────────────────────────┐
/// │  BER TAG BYTE DECODER                       │
/// ├─────────────────────────────────────────────┤
/// │  Bit Layout:  [CLASS][P/C][TAG NUMBER]      │
/// │               Bits 8-7  6   Bits 5-1        │
/// │                                             │
/// │  CLASS (bits 8-7):                          │
/// │    00 = Universal                           │
/// │    01 = Application                         │
/// │    10 = Context-specific                    │
/// │    11 = Private                             │
/// │                                             │
/// │  P/C (bit 6):                               │
/// │    0 = Primitive (simple value)             │
/// │    1 = Constructed (has children)           │
/// │                                             │
/// │  TAG NUMBER (bits 5-1):                     │
/// │    0-30 fits in these 5 bits                │
/// │    31 means "long form" (multi-byte)        │
/// └─────────────────────────────────────────────┘
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Asn1Tag {
    // --- Universal tags
    Integer = 0x02,
    OctetString = 0x04,
    Null = 0x05,
    ObjectIdentifier = 0x06,
    Sequence = 0x30,

    // --- Application-Specific Tags (SNMP) ---
    // These are context-specific and constructed
    IpAddress = 0x40, // [APPLICATION 0]
    Counter32 = 0x41, // [APPLICATION 1]
    Gauge32 = 0x42,   // [APPLICATION 2]
    TimeTicks = 0x43, // [APPLICATION 3]
    Opaque = 0x44,    // [APPLICATION 4]
    Counter64 = 0x46, // [APPLICATION 6]

    // --- Context-Specific Tags (SNMP PDUs) ---
    // These are context-specific and constructed
    GetRequest = 0xA0,     // [CONTEXT 0]
    GetNextRequest = 0xA1, // [CONTEXT 1]
    GetResponse = 0xA2,    // [CONTEXT 2]
    SetRequest = 0xA3,     // [CONTEXT 3]
    Trap = 0xA4,           // [CONTEXT 4]
    GetBulkRequest = 0xA5, // [CONTEXT 5]
    InformRequest = 0xA6,  // [CONTEXT 6]
    SnmpV2Trap = 0xA7,     // [CONTEXT 7]

    // exception types
    NoSuchObject = 0x80,
    NoSuchInstance = 0x81,
    EndOfMib = 0x82,
}

impl Asn1Tag {
    // only for debugging
    pub fn describe(&self) -> &'static str {
        match self {
            Asn1Tag::Integer => "Universal, Primitive, Tag 2 (INTEGER)",
            Asn1Tag::OctetString => "Universal, Primitive, Tag 4 (OCTET STRING)",
            Asn1Tag::Null => "Universal, Primitive, Tag 5 (NULL)",
            Asn1Tag::ObjectIdentifier => "Universal, Primitive, Tag 6 (OID)",
            Asn1Tag::Sequence => "Universal, Constructed, Tag 16 (SEQUENCE)",
            Asn1Tag::IpAddress => "Application, Primitive, Tag 0 (IpAddress)",
            Asn1Tag::Counter32 => "Application, Primitive, Tag 1 (Counter32)",
            Asn1Tag::Gauge32 => "Application, Primitive, Tag 2 (Gauge32)",
            Asn1Tag::TimeTicks => "Application, Primitive, Tag 3 (TimeTicks)",
            Asn1Tag::GetRequest => "Context, Constructed, Tag 0 (GetRequest)",
            Asn1Tag::GetNextRequest => "Context, Constructed, Tag 1 (GetNext)",
            Asn1Tag::GetResponse => "Context, Constructed, Tag 2 (Response)",
            Asn1Tag::GetBulkRequest => "Context, Constructed, Tag 5 (GetBulk)",
            _ => "Other",
        }
    }

    pub fn from_u8(tag_byte: u8) -> BerResult<Self> {
        match tag_byte {
            // Universal
            0x02 => Ok(Asn1Tag::Integer),
            0x04 => Ok(Asn1Tag::OctetString),
            0x05 => Ok(Asn1Tag::Null),
            0x06 => Ok(Asn1Tag::ObjectIdentifier),
            0x30 => Ok(Asn1Tag::Sequence),
            // Application
            0x40 => Ok(Asn1Tag::IpAddress),
            0x41 => Ok(Asn1Tag::Counter32),
            0x42 => Ok(Asn1Tag::Gauge32),
            0x43 => Ok(Asn1Tag::TimeTicks),
            0x44 => Ok(Asn1Tag::Opaque),
            0x46 => Ok(Asn1Tag::Counter64),
            // Context-Specific (PDUs)
            0xA0 => Ok(Asn1Tag::GetRequest),
            0xA1 => Ok(Asn1Tag::GetNextRequest),
            0xA2 => Ok(Asn1Tag::GetResponse),
            0xA3 => Ok(Asn1Tag::SetRequest),
            0xA4 => Ok(Asn1Tag::Trap),
            0xA5 => Ok(Asn1Tag::GetBulkRequest),
            0xA6 => Ok(Asn1Tag::InformRequest),
            0xA7 => Ok(Asn1Tag::SnmpV2Trap),
            0x80 => Ok(Asn1Tag::NoSuchObject),
            0x81 => Ok(Asn1Tag::NoSuchInstance),
            0x82 => Ok(Asn1Tag::EndOfMib),
            // Anything else is unsupported
            other => Err(BerError::UnsupportedType(other)),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct BerObject<'a> {
    pub tag: Asn1Tag,
    pub header_len: usize,
    pub value_len: usize,
    pub value: &'a [u8],
}

pub fn parse_ber_object(input: &[u8]) -> BerResult<(BerObject<'_>, &[u8])> {
    let (tag, after_tag) = parse_tag(input)?;
    let (value_len, after_length) = parse_length(after_tag)?;

    let total_header_len = (after_length.as_ptr() as usize) - (input.as_ptr() as usize);

    if after_length.len() < value_len {
        return Err(BerError::IncompleteData);
    }

    let (value, rest) = after_length.split_at(value_len);

    let object = BerObject {
        tag,
        header_len: total_header_len,
        value_len,
        value,
    };

    Ok((object, rest))
}

fn parse_tag(input: &[u8]) -> BerResult<(Asn1Tag, &[u8])> {
    let tag_byte = input.first().ok_or(BerError::IncompleteData)?;
    let tag = Asn1Tag::from_u8(*tag_byte)?;
    Ok((tag, &input[1..]))
}

fn parse_length(input: &[u8]) -> BerResult<(usize, &[u8])> {
    let len_byte = input.first().ok_or(BerError::IncompleteData)?;

    match *len_byte {
        // eighth bit is not 1 .
        0x00..=0x7F => {
            let value_len = *len_byte as usize;
            Ok((value_len, &input[1..]))
        }
        // -- Long form
        0x81..=0xFE => {
            let num_len_bytes = (len_byte & 0x7F) as usize;

            if num_len_bytes > 8 || input.len() < (1 + num_len_bytes) {
                return Err(BerError::MalformedLength);
            }

            let len_bytes_slice = &input[1..][..num_len_bytes];
            let rest = &input[(1 + num_len_bytes)..];

            let mut value_len = 0;
            for byte in len_bytes_slice {
                value_len = (value_len << 8) | (*byte as usize);
            }
            Ok((value_len, rest))
        }
        0x80 => Err(BerError::MalformedLength),
        0xFF => Err(BerError::MalformedLength),
    }
}

/// First Two Numbers: The first two numbers (e.g., 1 and 3) are compressed into a single byte using the formula (X * 40) + Y.
/// Example: For .1.3.6.1, the first byte is (1 * 40) + 3 = 43, which is 0x2B in hex.
/// All Other Numbers: Every number after the first two is encoded in a variable-length format.
/// A number is broken into 7-bit chunks.
/// The 8th bit (the most significant bit) of a byte is a "continuation" flag.
/// If the bit is 1, it means "this number continues in the next byte."
/// If the bit is 0, it means "this is the last byte for this number."
pub fn decode_oid(input: &[u8]) -> BerResult<Vec<u32>> {
    if input.is_empty() {
        return Err(BerError::IncompleteData);
    }

    let mut oid = Vec::with_capacity(10);

    // --- first byte
    let b1 = input[0];
    let x = (b1 / 40) as u32;
    let y = (b1 % 40) as u32;
    oid.push(x);
    oid.push(y);

    // ---2 . Rest of the bytes
    let mut current = &input[1..];
    while !current.is_empty() {
        let (sub_id, rest) = decode_oid_sub_id(current)?;
        oid.push(sub_id);
        current = rest;
    }
    Ok(oid)
}

fn decode_oid_sub_id(input: &[u8]) -> BerResult<(u32, &[u8])> {
    let mut sub_id = 0u32;
    let mut bytes_read = 0;

    for (i, &bytes) in input.iter().enumerate() {
        bytes_read = i + 1;

        if bytes_read > 5 {
            return Err(BerError::IntegerOverflow);
        }

        let values_bits = (bytes & 0x7F) as u32;

        sub_id = (sub_id << 7) | values_bits;

        if (bytes & 0x80) == 0 {
            // if 0 then this is the last bit -> continuation bit
            return Ok((sub_id, &input[bytes_read..]));
        }
    }
    Err(BerError::IncompleteData)
}
