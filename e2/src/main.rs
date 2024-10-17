fn pad(text: &[u8], size: usize) -> Vec<u8> {
    // Calculate the length of the text
    let length = text.len();
    
    // If the text is already a multiple of the size, return it as is
    if length % size == 0 {
        return text.to_vec();
    }
    
    // Calculate the padding needed
    let padding = size - (length % size);
    
    // Create a vector to hold the padded string
    let mut padded_string = Vec::from(text);
    
    // Append the padding bytes
    padded_string.extend(vec![padding as u8; padding]);
    
    padded_string
}

fn main() {
    let given = b"YELLOW SUBMARINE";
    let required_length = 20; // say
    let padded_string = pad(given, required_length);
    
    println!("Given: {:?}", String::from_utf8_lossy(given));
    println!("Length: {}", given.len());
    println!("Required Length: {}", required_length);
    println!("Padded: {:?}", padded_string);
}