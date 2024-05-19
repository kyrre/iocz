use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use tfhe::{prelude::*, CompactPublicKey, FheBool, FheUint32, FheUint8};

type Uint8 = FheUint8;
type Bool = FheBool;

/// A structure representing a 256-bit FHE encrypted integer
#[derive(Clone)]
pub struct FheUint256 {
    pub data: [Uint8; 32],
}

impl FheUint256 {
    /// Compares two FheUint256 values for equality
    fn eq(&self, rhs: &FheUint256, default_false: &FheBool) -> FheBool {
        // Comparing each byte for equality and reducing the result with a logical AND
        self.data
            .iter()
            .zip(rhs.data.iter())
            .map(|(a, b)| a.eq(b))
            .reduce(|acc, x| acc & x)
            .unwrap_or(default_false.clone())
    }
}

/// Converts a hexadecimal string to a FheUint256
pub fn hex_to_fhe(data: &str, public_key: &CompactPublicKey) -> FheUint256 {
    let bytes: [u8; 32] = hex::decode(data)
        .unwrap()
        .try_into()
        .expect("slice with incorrect length");

    FheUint256 {
        data: bytes.map(|x| FheUint8::encrypt(x, public_key)),
    }
}

/// A structure representing a value in the FHE dataframe
#[derive(Clone)]
pub struct Value {
    pub value: FheUint256,
}

/// Type alias for a row in the FHE dataframe
pub type Row = HashMap<String, Value>;

/// A structure representing a FHE dataframe
pub struct FheDataFrame {
    pub names: Vec<String>,
    pub rows: Vec<Row>,
    pub row_mask: Vec<Bool>,
    pub public_key: CompactPublicKey,
}

/// Enum representing a named expression in a query
pub enum NamedExpr {
    Column(String),
    Literal(FheUint256),
}

/// Enum representing an expression in a query
pub enum Expr {
    Eq(NamedExpr, NamedExpr),
}

/// Creates a named expression for a column
pub fn col(name: &str) -> NamedExpr {
    NamedExpr::Column(name.to_string())
}

/// Creates a named expression for a literal value
pub fn lit(value: FheUint256) -> NamedExpr {
    NamedExpr::Literal(value)
}

impl NamedExpr {
    /// Creates an equality expression
    pub fn eq(self, other: NamedExpr) -> Expr {
        Expr::Eq(self, other)
    }
}

impl FheDataFrame {
    /// Converts a string of hex data to a FheUint256
    pub fn to_fhe(&self, data: &str) -> FheUint256 {
        hex_to_fhe(data, &self.public_key)
    }

    /// Reads a CSV file and converts it to a FheDataFrame
    pub fn read_csv(file_path: &str, public_key: &CompactPublicKey) -> io::Result<Self> {
        // Open the file at the specified path
        let path = Path::new(file_path);
        let file = File::open(&path)?;
        let mut lines = io::BufReader::new(file).lines();

        // Read header line to get column names
        let header = lines.next().unwrap()?;
        let names: Vec<String> = header.split(',').map(|s| s.to_string()).collect();

        let mut rows = Vec::new();

        // Read each line and parse the values
        for line in lines {
            if let Ok(record) = line {
                let values: Vec<&str> = record.split(',').collect();
                let mut row = HashMap::new();

                for (i, value) in values.iter().enumerate() {
                    let fhe_value = hex_to_fhe(value, public_key);
                    row.insert(names[i].clone(), Value { value: fhe_value });
                }

                rows.push(row);
            }
        }

        let default_false = FheBool::encrypt(false, public_key);

        let n_rows = rows.len();

        Ok(FheDataFrame {
            names,
            rows,
            row_mask: vec![default_false; n_rows],
            public_key: public_key.clone(),
        })
    }

    /// Counts the number of rows in the dataframe
    pub fn count(&self) -> FheUint32 {
        let one = FheUint32::encrypt(1_u32, &self.public_key);
        let zero = FheUint32::encrypt(0_u32, &self.public_key);

        let mut sum: FheUint32 = zero.clone();

        for mask in &self.row_mask {
            sum = sum + mask.if_then_else(&one, &zero);
        }

        sum
    }

    /// Filters the rows of the dataframe based on an expression
    pub fn filter(&mut self, expr: Expr) -> &mut Self {
        let default_false = FheBool::encrypt(false, &self.public_key);
        for (i, row) in self.rows.iter().enumerate() {
            self.row_mask[i] =
                self.row_mask[i].clone() | self.eval_expr(&expr, row, &default_false);
        }

        self
    }

    /// Evaluates an expression for a given row
    fn eval_expr(&self, expr: &Expr, row: &Row, default_false: &Bool) -> Bool {
        match expr {
            Expr::Eq(left, right) => {
                let left = self.eval_named_expr(left, row);
                let right = self.eval_named_expr(right, row);

                left.eq(&right, default_false)
            }
        }
    }

    /// Evaluates a named expression for a given row
    fn eval_named_expr(&self, expr: &NamedExpr, row: &Row) -> FheUint256 {
        match expr {
            NamedExpr::Column(name) => row.get(name).unwrap().value.clone(),
            NamedExpr::Literal(value) => value.clone(),
        }
    }
}
