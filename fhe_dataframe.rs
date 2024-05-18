use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tfhe::{FheBool, FheUint8, PublicKey, prelude::*};

type Uint8 = FheUint8;
type Bool = FheBool;

#[derive(Clone)]
pub struct FheUint256 {
    pub data: [Uint8; 32],
}

impl From<(&[u8; 32], &PublicKey)> for [FheUint8; 32] {
    fn from(data: (&[u8; 32], &PublicKey)) -> Self {
        data.0.map(|x| FheUint8::encrypt(x, data.1))
    }
}

impl From<(&str, &PublicKey)> for [FheUint8; 32] {
    fn from(data: (&str, &PublicKey)) -> Self {
        let bytes: [u8; 32] = data.0.into();
        (bytes.as_ref(), data.1).into()
    }
}

impl From<(&str, &PublicKey)> for FheUint256 {
    fn from(data: (&str, &PublicKey)) -> Self {
        FheUint256 {
            data: (data.0, data.1).into(),
        }
    }
}

fn uint256_eq(a: &FheUint256, b: &FheUint256, default_false: &Bool) -> Bool {
    a.data
        .iter()
        .zip(b.data.iter())
        .map(|(a, b)| a.eq(b))
        .reduce(|acc, x| acc & x)
        .unwrap_or(default_false.clone())
}

#[derive(Clone)]
pub struct Value {
    pub value: FheUint256,
}

pub type Row = HashMap<String, Value>;

pub struct FheDataFrame {
    pub names: Vec<String>,
    pub rows: Vec<Row>,
    pub row_mask: Vec<Bool>,
    pub public_key: PublicKey,
}

pub enum NamedExpr {
    Column(String),
    Literal(FheUint256),
}

pub enum Expr {
    Eq(NamedExpr, NamedExpr),
}

pub fn col(name: &str) -> NamedExpr {
    NamedExpr::Column(name.to_string())
}

pub fn lit(value: FheUint256) -> NamedExpr {
    NamedExpr::Literal(value)
}

impl NamedExpr {
    pub fn eq(self, other: NamedExpr) -> Expr {
        Expr::Eq(self, other)
    }
}

impl FheDataFrame {
    pub fn count(&self) -> Uint8 {
        let one = FheUint8::encrypt(1_u8, &self.public_key);
        let zero = FheUint8::encrypt(0_u8, &self.public_key);

        let mut sum: Uint8 = zero.clone();

        for mask in &self.row_mask {
            sum = sum + mask.if_then_else(&one, &zero);
        }

        sum
    }

    // row filter op
    pub fn filter(&mut self, expr: Expr) -> &mut Self {
        let default_false = FheBool::encrypt(false, &self.public_key);
        for (i, row) in self.rows.iter().enumerate() {
            self.row_mask[i] =
                self.row_mask[i].clone() | self.eval_expr(&expr, row, &default_false);
        }

        self
    }

    fn eval_expr(&self, expr: &Expr, row: &Row, default_false: &Bool) -> Bool {
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

