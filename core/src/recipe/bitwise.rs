//! F-79 — Bitwise / arithmetic transforms. All in place, all reversible with a
//! sibling operation (XOR is its own inverse; `add`/`sub` and `rol`/`ror` pair).

/// XOR every byte with a repeating key. An empty key is a no-op.
pub fn xor(mut data: Vec<u8>, key: &[u8]) -> Vec<u8> {
    if !key.is_empty() {
        for (b, k) in data.iter_mut().zip(key.iter().cycle()) {
            *b ^= k;
        }
    }
    data
}

/// Add a constant to every byte, wrapping (CyberChef "ADD").
pub fn add(mut data: Vec<u8>, delta: u8) -> Vec<u8> {
    for b in &mut data {
        *b = b.wrapping_add(delta);
    }
    data
}

/// Subtract a constant from every byte, wrapping (CyberChef "SUB").
pub fn sub(mut data: Vec<u8>, delta: u8) -> Vec<u8> {
    for b in &mut data {
        *b = b.wrapping_sub(delta);
    }
    data
}

/// Rotate every byte left by `bits` (mod 8); `left = false` rotates right.
pub fn rotate(mut data: Vec<u8>, left: bool, bits: u32) -> Vec<u8> {
    let n = bits % 8;
    if n != 0 {
        for b in &mut data {
            *b = if left { b.rotate_left(n) } else { b.rotate_right(n) };
        }
    }
    data
}

/// Bitwise NOT of every byte.
pub fn not(mut data: Vec<u8>) -> Vec<u8> {
    for b in &mut data {
        *b = !*b;
    }
    data
}

/// Reverse the byte order of the whole buffer.
pub fn reverse(mut data: Vec<u8>) -> Vec<u8> {
    data.reverse();
    data
}
