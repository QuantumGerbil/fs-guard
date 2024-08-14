/// Converts a byte array to a hexadecimal string representation.
///
/// # Arguments
///
/// * `bytes` - A slice of bytes to be converted.
///
/// # Returns
///
/// A `String` containing the hexadecimal representation of the input bytes.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}
