use iocz::dataframe::{col, lit, FheDataFrame};
use tfhe::{generate_keys, set_server_key, ConfigBuilder};
use tfhe::{prelude::*, CompactPublicKey};

#[test]
fn test_fhe_dataframe_processing() {
    let config = ConfigBuilder::default()
        .use_custom_parameters(
            tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS,
            None,
        )
        .build();

    // Client-side key generation. just doing everything in one process for demo here
    let (client_key, server_key) = generate_keys(config);
    let public_key = CompactPublicKey::new(&client_key);

    set_server_key(server_key);

    let mut df = FheDataFrame::read_csv("process_logs.csv", &public_key).unwrap();

    let ioc_hash_value =
        df.to_fhe("027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745");

    let counts = df
        .filter(col("TargetProcessSHA256").eq(lit(ioc_hash_value)))
        .count();

    let c: u32 = counts.decrypt(&client_key);

    let expected_count = 2; // Set this to the expected count for your test case

    assert_eq!(
        c, expected_count,
        "The count of matching records should be equal to the expected value"
    );
}
