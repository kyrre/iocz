mod dataframe;
mod keys;

use dataframe::{col, FheDataFrame, lit};
use tfhe::{generate_keys, set_server_key, ConfigBuilder };
use tfhe::{prelude::*, CompactPublicKey };

fn main() {

    let config = ConfigBuilder::default()
        .use_custom_parameters(
            tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS,
            None,
        )
        .build();

    // Client-side key generation. just doing everything in one process for the hackathon demo here
    let (client_key, server_key) = generate_keys(config);

    // todo use compact + compressed keys
    let public_key = CompactPublicKey::new(&client_key);


    set_server_key(server_key);

    // read raw data frame. here there should be some method that let you then 
    // specify which columns to encrypt and how to do it, e.g., hash domain names first
    let mut df = FheDataFrame::read_csv("process_logs.csv", &public_key).unwrap();


    // now we are builing the query to look for a specific hash value
    let ioc_hash_value = df.to_fhe(
            "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",
    );


    let counts = df
        .filter(col("TargetProcessSHA256").eq(lit(ioc_hash_value))
        )
        .count();


    // this is the result we are returning to the client
    let c: u32 = counts.decrypt(&client_key);

    println!("counts: {}", c);
}
