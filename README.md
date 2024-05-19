

The original goal of this project was to create a way to express detection queries on encrypted data using backend-agnostic APIs (e.g., Apache Spark, Snowflake, BigQuery, DuckDB, Polars, Theseus) like those provided by the Ibis Python DataFrame.

For example, suppose we have a detection query looking through security logs for evidence of an intrusion, such as a process with a specific hash value being executed in our environment. Typically, these logs are stored in S3 or ADSL using file formats like Iceberg or Delta Lake.

Here's a simple detection expressed using PySpark that generates a query to read a table, transform columns (to lowercase), and look for a specific hash value within a time period:

```python
events = (
    spark.read_table("db.process_table_name")
         .select(col("p_date"), lower(col("TargetProcessSHA256")))
         .where(col("p_date") > "2024-05-13")
         .where(col("TargetProcessSHA256") == "some_value")
         # .... more conditions here
)

```

Using Ibis, you can create DataFrame queries like this, and it will produce SQL for whatever backend you're working with (e.g., Snowflake, Postgres). This allows you to execute the same query on multiple systems:

DuckDB (small datasets)
Apache Spark (medium)
Theseus (huge)
When working with government agencies that can't share classified queries, the idea is to use an FHE DataFrame instead.


As of now only fhe 256 bit matching is implemented as a PoC using a half-baked dataframe api that i cooked up. 

```rust
let mut df = FheDataFrame::read_csv("process_logs.csv", &public_key).unwrap();


 // now we are builing the query to look for a specific hash value
 let ioc_hash_value = df.to_fhe(
"027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",
 );


 let counts = df.filter(col("TargetProcessSHA256").eq(lit(ioc_hash_value)))
     .count();


 // this is the result we are returning to the client
 let c: u32 = counts.decrypt(&client_key);

```