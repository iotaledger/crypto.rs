#[allow(dead_code)]

#[macro_use]
extern crate neon;
#[macro_use]
extern crate neon_serde;
#[macro_use]
extern crate serde_derive;

use crypto;

#[derive(Serialize, Deserialize, Debug)]
struct Cmd {
    feature: String,
    function: String,
    size: f64,
    payload: String,
    returns: String,
}

export! {
    fn sync(cmd: Cmd) -> String {
        match &cmd.feature as &str {
            "rand" => {
                let mut buf = cmd.size.to_le_bytes();
                crypto::rand::fill(&mut buf).map_err(|e| e.to_string());
                format!("{:?}", buf)
            },
            "ed25519" => {
                match &cmd.function as &str {
                    "generate" => {
                        let kk = crypto::ed25519::SecretKey::generate().unwrap();
                        format!("{:?}", kk)
                    },
                    _ => {
                        format!("4ed")
                    },         
                }       
            },
            _ => {
                format!("4")
            },
        }
    }    
}
