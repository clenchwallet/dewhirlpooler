# Public example

Transaction:

```text
18c999772ed82bf7753bdce9021cfa68b505de36344ce81f77d0c436b7135892
```

Run the local web service with a Fulcrum connection, then submit:

- Trace depth: `2`
- Transaction limit: `50`
- Output limit: `250`
- History-check limit: `250`

The reference result contains eight transactions and six candidate Whirlpool
rounds. It is partial because the depth limit is reached.

Amounts, fees, scripts, block facts, and direct spends are
observed public-chain data. Protocol roles and links across a coinjoin are
evidence-labelled heuristics. Solid graph edges are direct spends; dashed
edges are possible coinjoin-crossing links.
