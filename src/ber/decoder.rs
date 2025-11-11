use crate::ber::{BerError, BerResult};

pub fn decode_integer(input: &[u8]) -> BerResult<i32> {
    if input.is_empty() {
        return Err(BerError::IncompleteData);
    }

    // Reject anything that can't fit in i32
    // 4 bytes always fits
    // 5 bytes only if it's padding
    if input.len() > 4 {
        // 5 bytes valid if first byte is padding
        if input.len() == 5 {
            if input[0] == 0x00 && (input[1] & 0x80) != 0 {
                // valid continue
            } else if input[0] == 0xFF && (input[1] & 0x80) == 0 {
                // valid continue
            } else {
                return Err(BerError::IntegerOverflow);
            }
        } else {
            return Err(BerError::IntegerOverflow);
        }
    }

    let mut value: i32 = if (input[0] & 0x80) != 0 { -1 } else { 0 };

    for &byte in input {
        value = (value << 8) | (byte as i32);
    }

    Ok(value)
}

pub fn decode_unsigned_integer(input: &[u8]) -> BerResult<u32> {
    if input.is_empty() {
        return Err(BerError::IncompleteData);
    }

    if input.len() > 5 {
        return Err(BerError::IntegerOverflow);
    }

    if input.len() == 5 && input[0] != 0x00 {
        return Err(BerError::IntegerOverflow);
    }

    let mut value = 0;

    for &byte in input {
        value = (value << 8) | (byte as u32);
    }
    Ok(value)
}

pub fn decode_unsigned_integer64(input: &[u8]) -> BerResult<u64> {
    if input.is_empty() {
        return Err(BerError::IncompleteData);
    }

    if input.len() > 9 {
        return Err(BerError::IntegerOverflow);
    }

    if input.len() == 9 && input[0] != 0x00 {
        return Err(BerError::IntegerOverflow);
    }

    let mut value = 0;

    for &byte in input {
        value = (value << 8) | (byte as u64);
    }
    Ok(value)
}
