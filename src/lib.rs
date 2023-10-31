use sha2::{Sha256, Digest};

pub fn apikey_verify(api_key: &str) -> bool {
    //let api_key = api_key.to_string();
    // check api_key length equal to 44 bytes.
    if api_key.len() != 44 {
        return false;
    }
    // verify checksum.
    let mut hasher = Sha256::new();
    hasher.update(&api_key[..38]);
    let result = hasher.finalize();
    if result[..3] != hex::decode(&api_key[38..]).unwrap() {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_apikey_verify() {
        let api_key = "zkwork422fb9f5a0b43816af8ef0433ab987bcd72bd2";
        assert_eq!(true, apikey_verify(api_key));
        let api_key = "zkwork422fb9f5a0b43816af8ef0433ab987bcd72bd1";
        assert_eq!(false, apikey_verify(api_key));
    }
}
