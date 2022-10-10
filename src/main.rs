use ckb_hash::blake2b_256;
use clap::Parser;
use std::{collections::HashMap, error::Error as StdErr};

use ckb_jsonrpc_types as json_types;
use ckb_sdk::{
    constants::SIGHASH_TYPE_HASH,
    rpc::{
        ckb_indexer::{ScriptType, SearchKey},
        CkbRpcClient,
    },
    traits::{
        CellCollector, DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
        SecpCkbRawKeySigner,
    },
    tx_builder::{
        balance_tx_capacity, fill_placeholder_witnesses, transfer::CapacityTransferBuilder,
        unlock_tx, CapacityBalancer, TxBuilder,
    },
    unlock::{ScriptUnlocker, SecpSighashUnlocker},
    IndexerRpcClient, ScriptId, SECP256K1,
};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, Capacity, ScriptHashType, TransactionBuilder, TransactionView},
    packed::{CellInput, CellOutput, OutPoint, Script, Transaction, Uint64, WitnessArgs},
    prelude::*,
    H256,
};

mod cell_collector;
mod tx_dep_provider;

/// Send some chained transaction
/// # Example:
///     ./target/debug/chained_tx \
///       --sender-key <key-hex> \
///       --tx-hash <hash-hex> \
///       --tx-count <number>
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// The sender private key (hex string)
    #[clap(
        long,
        value_name = "KEY",
        default_value = "0000000000000000000000000000000000000000000000000000000000000001"
    )]
    sender_key: H256,

    #[clap(
        long,
        value_name = "TX",
        default_value = "0000000000000000000000000000000000000000000000000000000000000000"
    )]
    tx_hash: H256,
    #[clap(long, value_name = "COUNT", default_value = "4")]
    tx_count: i32,

    /// CKB rpc url
    #[clap(long, value_name = "URL", default_value = "https://testnet.ckb.dev")]
    ckb_rpc: String,

    /// CKB indexer rpc url
    #[clap(
        long,
        value_name = "URL",
        default_value = "https://testnet.ckb.dev/indexer"
    )]
    ckb_indexer: String,
}

fn main() -> Result<(), Box<dyn StdErr>> {
    let args = Args::parse();
    let sender_key = secp256k1::SecretKey::from_slice(args.sender_key.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))?;
    let sender = {
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
        let hash160 = blake2b_256(&pubkey.serialize()[..])[0..20].to_vec();
        Script::new_builder()
            .code_hash(SIGHASH_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(hash160).pack())
            .build()
    };

    let mut ckb_rpc_client = CkbRpcClient::new(&args.ckb_rpc);
    let mut ckb_indexer_client = IndexerRpcClient::new(&args.ckb_indexer);

    let cells = ckb_indexer_client
        .get_cells(
            SearchKey {
                script: sender.clone().into(),
                script_type: ScriptType::Type,
                filter: None,
            },
            ckb_sdk::rpc::ckb_indexer::Order::Asc,
            1.into(),
            None,
        )
        .unwrap();

    if cells.objects.len() <= 0 {
        println!("sender have no cells");
        return Ok(())
    }

    let mut json_tx = if args.tx_hash == H256::from([0u8; 32]) {
        let tx = build_init_tx(&args, sender.clone(), sender_key)?;
        // Send transaction
        let json_tx = json_types::TransactionView::from(tx.clone());
        println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());
        let outputs_validator = Some(json_types::OutputsValidator::Passthrough);
        let tx_hash = ckb_rpc_client
            .send_transaction(json_tx.clone().inner, outputs_validator)
            .expect("send transaction");
        println!(">>> tx 0x{} sent! <<<", hex::encode(&tx_hash));
        json_tx
    } else {
        let mut rpc = CkbRpcClient::new(&args.ckb_rpc);
        let tx_hash = args.tx_hash.0;
        let json_tx = rpc
            .get_transaction(tx_hash.into())
            .unwrap()
            .unwrap()
            .transaction
            .unwrap();
        json_tx
    };

    for _ in 0..args.tx_count {
        let outpoint_1 = OutPoint::new_builder()
            .tx_hash(json_tx.hash.0.pack())
            .index(0u32.pack())
            .build();
        let outpoint_2 = OutPoint::new_builder()
            .tx_hash(json_tx.hash.0.pack())
            .index(1u32.pack())
            .build();
        let outpoint_3 = OutPoint::new_builder()
            .tx_hash(json_tx.hash.0.pack())
            .index(2u32.pack())
            .build();
        let output_1 = json_tx.inner.outputs[0].clone();
        let output_2 = json_tx.inner.outputs[1].clone();
        let output_3 = json_tx.inner.outputs[2].clone();
        let outputs_data = {
            let data1 = Bytes::from(json_tx.inner.outputs_data[0].as_bytes().to_vec());
            let data2 = Bytes::from(json_tx.inner.outputs_data[1].as_bytes().to_vec());
            let data3 = Bytes::from(json_tx.inner.outputs_data[2].as_bytes().to_vec());
            [data1, data2, data3]
        };
        let tx = build_dep_tx(
            &args,
            sender.clone(),
            sender_key,
            json_tx.inner.into(),
            &[outpoint_1, outpoint_2, outpoint_3],
            &[output_1.into(), output_2.into(), output_3.into()],
            &outputs_data,
        )?;

        // Send transaction
        json_tx = json_types::TransactionView::from(tx.clone());
        println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());
        let outputs_validator = Some(json_types::OutputsValidator::Passthrough);
        let tx_hash = ckb_rpc_client
            .send_transaction(json_tx.inner.clone(), outputs_validator)
            .expect("send transaction");
        println!(">>> tx 0x{} sent! <<<", hex::encode(&tx_hash));
        std::thread::sleep(std::time::Duration::from_millis(200))
    }
    Ok(())
}

fn build_init_tx(
    args: &Args,
    sender: Script,
    sender_key: secp256k1::SecretKey,
) -> Result<TransactionView, Box<dyn StdErr>> {
    // Build ScriptUnlocker
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![sender_key]);
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    let mut unlockers = HashMap::default();
    unlockers.insert(
        sighash_script_id,
        Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
    );

    // Build CapacityBalancer
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer = CapacityBalancer::new_simple(sender.clone(), placeholder_witness, 1000);

    // Build:
    //   * CellDepResolver
    //   * HeaderDepResolver
    //   * CellCollector
    //   * TransactionDependencyProvider
    let mut ckb_rpc_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    let cell_dep_resolver = {
        let genesis_block = ckb_rpc_client.get_block_by_number(0.into())?.unwrap();
        DefaultCellDepResolver::from_genesis(&BlockView::from(genesis_block))?
    };
    let header_dep_resolver = DefaultHeaderDepResolver::new(args.ckb_rpc.as_str());
    let mut cell_collector =
        DefaultCellCollector::new(args.ckb_indexer.as_str(), args.ckb_rpc.as_str());
    let tx_dep_provider = tx_dep_provider::TxDep::new(args.ckb_rpc.as_str(), 10);

    // Build the transaction
    let output_1 = CellOutput::new_builder().lock(sender.clone()).build();
    let output_2 = CellOutput::new_builder().lock(sender.clone()).build();
    let capacity_1 = output_1
        .occupied_capacity(Capacity::bytes(8).unwrap())
        .unwrap();
    let capacity_2 = output_2
        .occupied_capacity(Capacity::bytes(8).unwrap())
        .unwrap();
    let output_1 = output_1.as_builder().capacity(capacity_1.pack()).build();
    let output_2 = output_2.as_builder().capacity(capacity_2.pack()).build();

    println!("capacity: {}", capacity_1.as_u64());
    let builder = CapacityTransferBuilder::new(vec![
        (
            output_1,
            Bytes::from(
                Uint64::from_slice(&(1 as u64).to_le_bytes())
                    .unwrap()
                    .as_bytes(),
            ),
        ),
        (
            output_2,
            Bytes::from(
                Uint64::from_slice(&(1000 as u64).to_le_bytes())
                    .unwrap()
                    .as_bytes(),
            ),
        ),
    ]);

    let (tx, still_locked_groups) = builder.build_unlocked(
        &mut cell_collector,
        &cell_dep_resolver,
        &header_dep_resolver,
        &tx_dep_provider,
        &balancer,
        &unlockers,
    )?;
    assert!(still_locked_groups.is_empty());
    Ok(tx)
}

fn build_dep_tx(
    args: &Args,
    sender: Script,
    sender_key: secp256k1::SecretKey,
    last_tx: Transaction,
    out_points: &[OutPoint],
    cell_output: &[CellOutput],
    inputs_data: &[Bytes],
) -> Result<TransactionView, Box<dyn StdErr>> {
    // Build ScriptUnlocker
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![sender_key]);
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    let mut unlockers = HashMap::default();
    unlockers.insert(
        sighash_script_id,
        Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
    );

    // Build CapacityBalancer
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer = CapacityBalancer::new_simple(sender.clone(), placeholder_witness, 1000);

    // Build:
    //   * CellDepResolver
    //   * HeaderDepResolver
    //   * CellCollector
    //   * TransactionDependencyProvider
    let mut ckb_rpc_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    let cell_dep_resolver = {
        let genesis_block = ckb_rpc_client.get_block_by_number(0.into())?.unwrap();
        DefaultCellDepResolver::from_genesis(&BlockView::from(genesis_block))?
    };
    let header_dep_resolver = DefaultHeaderDepResolver::new(args.ckb_rpc.as_str());
    let mut cell_collector =
        DefaultCellCollector::new(args.ckb_indexer.as_str(), args.ckb_rpc.as_str());
    cell_collector.apply_tx(last_tx)?;
    let mut tx_dep_provider = tx_dep_provider::TxDep::new(args.ckb_rpc.as_str(), 10);
    for i in 0..out_points.len() {
        tx_dep_provider.add_cell(
            out_points[i].clone(),
            cell_output[i].clone(),
            inputs_data[i].clone(),
        )
    }
    let input_1 = CellInput::new_builder()
        .previous_output(out_points[0].clone())
        .build();
    let input_2 = CellInput::new_builder()
        .previous_output(out_points[1].clone())
        .build();
    // Build the transaction
    let output_1 = CellOutput::new_builder()
        .lock(sender.clone())
        .capacity((6900000000u64).pack())
        .build();
    let output_2 = CellOutput::new_builder()
        .lock(sender.clone())
        .capacity((6900000000u64).pack())
        .build();

    let outputs_data: Vec<ckb_types::packed::Bytes> = inputs_data
        .iter()
        .take(2)
        .map(|data| {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&data);

            Bytes::from(
                Uint64::from_slice(&(u64::from_le_bytes(buf) + 1).to_le_bytes())
                    .unwrap()
                    .as_bytes(),
            )
            .pack()
        })
        .collect();

    let base_tx = TransactionBuilder::default()
        .set_inputs([input_1, input_2].to_vec())
        .set_outputs([output_1, output_2].to_vec())
        .set_outputs_data(outputs_data)
        .build();

    let (tx_filled_witnesses, _) =
        fill_placeholder_witnesses(base_tx, &tx_dep_provider, &unlockers)?;

    let tx = balance_tx_capacity(
        &tx_filled_witnesses,
        &balancer,
        &mut cell_collector,
        &tx_dep_provider,
        &cell_dep_resolver,
        &header_dep_resolver,
    )?;
    let (tx, still_locked_groups) = unlock_tx(tx, &tx_dep_provider, &unlockers)?;
    assert!(still_locked_groups.is_empty());
    Ok(tx)
}

#[cfg(test)]
mod test {
    use ckb_hash::blake2b_256;
    use ckb_sdk::{constants::SIGHASH_TYPE_HASH, Address, AddressPayload, NetworkType, SECP256K1};
    use ckb_types::{bytes::Bytes, core::ScriptHashType, prelude::Pack};

    #[test]
    fn generate_addr() {
        let sk = secp256k1::SecretKey::from_slice(
            hex::decode("9d5c9935429b2016cff62911e8ba240ed4f3f122a5729bd89d0736977272fcec")
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        println!("sk: {}", hex::encode(sk.as_ref()));
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sk);
        let hash160 = blake2b_256(&pubkey.serialize()[..])[0..20].to_vec();
        println!("pk: {}", hex::encode(&hash160));
        let addr_payload = AddressPayload::new_full(
            ScriptHashType::Type.into(),
            SIGHASH_TYPE_HASH.pack(),
            Bytes::from(hash160),
        );

        let addr = Address::new(NetworkType::Testnet, addr_payload, true);
        // ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqdlypz994jvvkgmalgwyer72pezegee3xqszs6nt
        println!("addr: {}", addr);
    }
}
