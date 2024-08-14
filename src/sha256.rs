/// Computes the SHA-256 hash of the input data.
/// 
/// This function takes a byte slice as input, applies the SHA-256 hashing algorithm,
/// and returns a 32-byte array representing the hash.
///
/// # Arguments
///
/// * `input` - A byte slice containing the data to be hashed.
///
/// # Returns
///
/// A 32-byte array containing the SHA-256 hash of the input data.
pub fn sha256(input: &[u8]) -> [u8; 32] {
    // Initial hash values as defined in the SHA-256 specification
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Pad the input message to prepare it for processing
    let padded = pad_message(input);

    // Process each 512-bit block of the padded message
    for block in padded.chunks(64) {
        compress(&mut h, block);
    }

    // Convert the final hash values into a byte array
    let mut hash = [0u8; 32];
    for (i, &val) in h.iter().enumerate() {
        hash[i * 4..(i + 1) * 4].copy_from_slice(&val.to_be_bytes());
    }

    hash
}

/// Pads the input message according to the SHA-256 specification.
///
/// The padding ensures that the message length is congruent to 448 modulo 512,
/// followed by appending the original message length as a 64-bit integer.
///
/// # Arguments
///
/// * `message` - A byte slice containing the original message.
///
/// # Returns
///
/// A `Vec<u8>` containing the padded message.
fn pad_message(message: &[u8]) -> Vec<u8> {
    let mut padded = message.to_vec();
    
    // Step 1: Append a single '1' bit (0x80 in hexadecimal)
    padded.push(0x80);
    
    // Step 2: Append '0' bits until the length is 448 modulo 512
    while (padded.len() * 8) % 512 != 448 {
        padded.push(0);
    }
    
    // Step 3: Append the original message length as a 64-bit big-endian integer
    let bit_length = (message.len() * 8) as u64;
    padded.extend_from_slice(&bit_length.to_be_bytes());
    
    padded
}

/// Prepares the message schedule for the compression function.
///
/// This function expands the 512-bit block into a series of 64 32-bit words
/// used during the compression rounds.
///
/// # Arguments
///
/// * `block` - A 64-byte slice representing a 512-bit block of the padded message.
///
/// # Returns
///
/// An array of 64 `u32` words used in the compression function.
fn message_schedule(block: &[u8]) -> [u32; 64] {
    let mut w = [0u32; 64];
    
    // Initialize the first 16 words
    for i in 0..16 {
        w[i] = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
    }
    
    // Compute the remaining words
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    
    w
}

/// Performs the SHA-256 compression function on a single block.
///
/// This function updates the hash values by processing a 512-bit block
/// using the message schedule and predefined constants.
///
/// # Arguments
///
/// * `h` - A mutable reference to an array of 8 `u32` values representing the current hash state.
/// * `block` - A 64-byte slice representing a 512-bit block of the padded message.
fn compress(hash_state: &mut [u32; 8], block: &[u8]) {
    // Constants for SHA-256
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let mut a = hash_state[0];
    let mut b = hash_state[1];
    let mut c = hash_state[2];
    let mut d = hash_state[3];
    let mut e = hash_state[4];
    let mut f = hash_state[5];
    let mut g = hash_state[6];
    let mut h = hash_state[7];

    let w = message_schedule(block);

    // Perform 64 rounds of hashing
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h.wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    // Update the hash state
    hash_state[0] = hash_state[0].wrapping_add(a);
    hash_state[1] = hash_state[1].wrapping_add(b);
    hash_state[2] = hash_state[2].wrapping_add(c);
    hash_state[3] = hash_state[3].wrapping_add(d);
    hash_state[4] = hash_state[4].wrapping_add(e);
    hash_state[5] = hash_state[5].wrapping_add(f);
    hash_state[6] = hash_state[6].wrapping_add(g);
    hash_state[7] = hash_state[7].wrapping_add(h);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sha256_hello_world() {
        let input = b"hello world";
        let expected_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let hash = sha256(input);
        let output_hex = bytes_to_hex(&hash);
        assert_eq!(output_hex, expected_hex);
    }

    #[test]
    fn test_sha256_empty_string() {
        let input = b"";
        let expected_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let hash = sha256(input);
        let output_hex = bytes_to_hex(&hash);
        assert_eq!(output_hex, expected_hex);
    }

    #[test]
    fn test_sha256_single_character() {
        let input = b"a";
        let expected_hex = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";
        let hash = sha256(input);
        let output_hex = bytes_to_hex(&hash);
        assert_eq!(output_hex, expected_hex);
    }
}
