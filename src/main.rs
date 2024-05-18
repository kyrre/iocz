use hex::FromHex;
use std::collections::HashMap;
use std::convert::TryInto;
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint32, FheUint8, PublicKey};

fn sha256_str_to_bytes(hash_value: &str) -> Result<[u8; 32], hex::FromHexError> {
    let bytes = Vec::from_hex(hash_value)?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .expect("slice with incorrect length");
    Ok(array)
}

trait IfThenElse {
    fn if_then_else<T>(self, then_branch: T, else_branch: T) -> T;
}

impl IfThenElse for bool {
    fn if_then_else<T>(self, then_branch: T, else_branch: T) -> T {
        if self {
            then_branch
        } else {
            else_branch
        }
    }
}

// type Uint8 = FheUint8;
type Uint8 = u8;
type Bool = bool;

#[derive(Clone)]
struct FheUint256 {
    data: [Uint8; 32],
}

fn uint256_eq(a: &FheUint256, b: &FheUint256, default_false: Bool) -> Bool {
    a.data
        .iter()
        .zip(b.data.iter())
        .map(|(a, b)| a.eq(b))
        .reduce(|acc, x| acc & x)
        .unwrap_or(default_false)
}

impl FheUint256 {}

struct Value {
    value: FheUint256,
}

type Row = HashMap<String, Value>;

struct FheDataFrame {
    names: Vec<String>,
    rows: Vec<Row>,
    row_mask: Vec<Bool>,
}

enum NamedExpr {
    Column(String),
    Literal(FheUint256),
}

enum Expr {
    Eq(NamedExpr, NamedExpr),
}
impl FheDataFrame {
    // mask ...

    fn count(&self) -> Uint8 {
        let mut sum: Uint8 = 0;

        for mask in &self.row_mask {
            println!("mask = {}", mask);
            sum = sum + mask.if_then_else(1, 0);
        }

        return 0;
    }

    // row filter op
    fn filter(&mut self, expr: Expr) -> &mut Self {
        for (i, row) in self.rows.iter().enumerate() {
            for (column_name, value) in row.iter() {
                self.row_mask[i] = self.row_mask[i] | self.eval_expr(&expr, row, false);
                println!("{}, {:?}", column_name, value.value.data);
            }
        }

        self
    }

    fn new() -> Self {
        FheDataFrame {
            names: Vec::new(),
            rows: Vec::new(),
            row_mask: Vec::new(),
        }
    }

    fn eval_expr(&self, expr: &Expr, row: &Row, default_false: Bool) -> Bool {
        match expr {
            Expr::Eq(left, right) => {
                let left = self.eval_named_expr(left, row);
                let right = self.eval_named_expr(right, row);

                uint256_eq(&left, &right, default_false)
            }
        }
    }

    fn eval_named_expr(&self, expr: &NamedExpr, row: &Row) -> FheUint256 {
        match expr {
            NamedExpr::Column(name) => row.get(name).unwrap().value.clone(),
            NamedExpr::Literal(value) => value.clone(),
        }
    }
}

fn get_test_data() -> [u8; 32] {
    let hash_hex = "a3c16a54e2e8d6dfb0f1cc1d4f69f9a9f1b0f6a7929fb923f2e4b6b58c985a29";

    sha256_str_to_bytes(hash_hex).unwrap()
}

fn create_test_instance() -> FheDataFrame {
    // Create a test instance of FheUint256
    let fhe_value = vec![
        FheUint256 {
        data: sha256_str_to_bytes(
            "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",
        )
        .unwrap(),
    }];

    // let value_instance = Value { value: fhe_value };


    let mut row_instance = Row::new();
    for value in fhe_value {
        row_instance.insert("TargetProcessSHA256".to_string(), Value{value: value});
    };

    // Create a FheDataFrame instance
    let dataframe_instance = FheDataFrame {
        names: vec!["TargetProcessSHA256".to_string()],
        rows: vec![row_instance],
        row_mask: vec![false, false, false, false, false],
    };

    dataframe_instance
}


fn main() {
    let mut df = create_test_instance();

    let counts = df
        .filter(Expr::Eq(
            NamedExpr::Column("TargetProcessSHA256".to_string()),
            NamedExpr::Literal(FheUint256 {
                data: sha256_str_to_bytes(
                    "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",
                )
                .unwrap(),
            }),
        ))
        .count();

    println!("{:?}", counts);

    //let config = ConfigBuilder::default().build();

    //// Client-side
    //let (client_key, server_key) = generate_keys(config);

    //let public_key = PublicKey::new(&client_key);

    //let data = get_test_data();
    //let data2 = get_test_data();

    //let encrypted_data = data.map(|x| FheUint8::encrypt(x, &public_key));

    // //Server-side
    // set_server_key(server_key);

    // let server_encrypted_data = data2.map(|x| FheUint8::encrypt(x, &public_key));

    // let result = encrypted_data
    //     .iter()
    //     .zip(server_encrypted_data.iter())
    //     .map(|(a, b)| a.eq(b))
    //     .reduce(|acc, x| acc & x)
    //     .unwrap_or(FheBool::encrypt(false, &public_key));

    // let decrypted_result = result.decrypt(&client_key);

    // if decrypted_result {
    //     println!("The two SHA256 hashes are the same.")
    // } else {
    //     println!("The two SHA256 hashes are not the same.")
    // }
}
