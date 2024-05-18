use bincode;
use hex::FromHex;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::File;
use std::io::{Read, Write};
use tfhe::boolean::public_key;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint32, FheUint8, PublicKey};
use tfhe::{prelude::*, ClientKey, ServerKey};

fn sha256_str_to_bytes(hash_value: &str) -> Result<[u8; 32], hex::FromHexError> {
    let bytes = Vec::from_hex(hash_value)?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .expect("slice with incorrect length");
    Ok(array)
}

fn sha256_str_to_fhe(hash_value: &str, public_key: &PublicKey) -> [FheUint8; 32] {
    let data = sha256_str_to_bytes(hash_value).unwrap();

    data.map(|x| FheUint8::encrypt(x, public_key))
}

//trait IfThenElse {
//    fn if_then_else<T>(self, then_branch: T, else_branch: T) -> T;
//}
//
//impl IfThenElse for bool {
//    fn if_then_else<T>(self, then_branch: T, else_branch: T) -> T {
//        if self {
//            then_branch
//        } else {
//            else_branch
//        }
//    }
//}

type Uint8 = FheUint8;
// type Uint8 = u8;
type Bool = FheBool;

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
    public_key: PublicKey,
}

enum NamedExpr {
    Column(String),
    Literal(FheUint256),
}

enum Expr {
    Eq(NamedExpr, NamedExpr),
}

fn col(name: &str) -> NamedExpr {
    NamedExpr::Column(name.to_string())
}

fn lit(value: FheUint256) -> NamedExpr {
    NamedExpr::Literal(value)
}

impl NamedExpr {
    fn eq(self, other: NamedExpr) -> Expr {
        Expr::Eq(self, other)
    }
}

impl FheDataFrame {
    fn count(&self) -> Uint8 {
        let one = FheUint8::encrypt(1_u8, &self.public_key);
        let zero = FheUint8::encrypt(0_u8, &self.public_key);

        let mut sum: Uint8 = zero.clone();

        for mask in &self.row_mask {
            sum = sum + mask.if_then_else(&one, &zero);
        }

        sum
    }

    // row filter op
    fn filter(&mut self, expr: Expr) -> &mut Self {
        let default_false = FheBool::encrypt(false, &self.public_key);
        for (i, row) in self.rows.iter().enumerate() {
            self.row_mask[i] =
                self.row_mask[i].clone() | self.eval_expr(&expr, row, default_false.clone());
        }

        self
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

fn create_test_instance(public_key: PublicKey) -> FheDataFrame {
    // Create a test instance of FheUint256
    let values = vec![
        FheUint256 {
            data: sha256_str_to_fhe(
                "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",
                &public_key,
            ),
        },
        FheUint256 {
            data: sha256_str_to_fhe(
                "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",
                &public_key,
            ),
        },
        FheUint256 {
            data: sha256_str_to_fhe(
                "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a746",
                &public_key,
            ),
        },
        FheUint256 {
            data: sha256_str_to_fhe(
                "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a744",
                &public_key,
            ),
        },
        FheUint256 {
            data: sha256_str_to_fhe(
                "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a743",
                &public_key,
            ),
        },
    ];

    // let value_instance = Value { value: fhe_value };

    let mut rows: Vec<Row> = Vec::new();

    for value in values {
        let mut row_instance = Row::new();
        row_instance.insert("TargetProcessSHA256".to_string(), Value { value: value });
        rows.push(row_instance);
    }

    let default_false = FheBool::encrypt(false, &public_key);

    // Create a FheDataFrame instance
    let dataframe_instance = FheDataFrame {
        names: vec!["TargetProcessSHA256".to_string()],
        rows: rows,
        row_mask: vec![
            default_false.clone(),
            default_false.clone(),
            default_false.clone(),
            default_false.clone(),
            default_false.clone(),
        ],
        public_key: public_key,
    };

    dataframe_instance
}

fn dump_to_file<T: Serialize>(key: &T, filename: &str) {
    let encoded: Vec<u8> = bincode::serialize(key).unwrap();
    let mut file = File::create(filename).unwrap();
    file.write_all(&encoded).unwrap();
}

fn read_from_file<T: DeserializeOwned>(filename: &str) -> T {
    let mut file = File::open(filename).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();
    let key: T = bincode::deserialize(&buffer).unwrap();
    key
}

fn main() {
    let config = ConfigBuilder::default().build();

    // Client-side
    //let (client_key, server_key) = generate_keys(config);
    //let public_key = PublicKey::new(&client_key);

    //dump_to_file(&client_key, "client_key.bincode");
    //dump_to_file(&server_key, "server_key.bincode");
    //dump_to_file(&public_key, "public_key.bincode");

    let client_key: ClientKey = read_from_file("client_key.bincode");
    let server_key: ServerKey = read_from_file("server_key.bincode");
    let public_key: PublicKey = read_from_file("public_key.bincode");

    set_server_key(server_key);

    let mut df = create_test_instance(public_key);

    let counts = df
        .filter(col("TargetProcessSHA256").eq(lit(FheUint256 {
            data: sha256_str_to_fhe(
                "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",
                &df.public_key,
            ),
        })))
        .count();

    let c: u8 = counts.decrypt(&client_key);

    println!("counts: {}", c);
}
