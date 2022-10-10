# Chained-Tx-Example

```
Send some chained transaction
    Example:
    ./target/release/chained_tx \
        --sender-key <key-hex> \
        --tx-hash <hash-hex> \
        --tx-count <number>

USAGE:
    chained_tx [OPTIONS]

OPTIONS:
        --ckb-indexer <URL>    CKB indexer rpc url [default: https://testnet.ckb.dev/indexer]
        --ckb-rpc <URL>        CKB rpc url [default: https://testnet.ckb.dev]
    -h, --help                 Print help information
        --sender-key <KEY>     The sender private key (hex string) [default:
                               0000000000000000000000000000000000000000000000000000000000000001]
        --tx-count <COUNT>     [default: 4]
        --tx-hash <TX>         [default:
                               0000000000000000000000000000000000000000000000000000000000000000]
    -V, --version              Print version information
```

## intro

every transaction have three input cells and three output cells, the data of first two output cells is the data of first input cells plus one, and the third cell is use for pay transaction fee.

if you have send some transactions before, you can specify `--tx-hash` to continue contrcuct chained-tx with the transaction.
