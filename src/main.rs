use std::{collections::BTreeMap, str::FromStr};

use bitcoin::{
    absolute,
    consensus::{deserialize, serialize},
    key::Secp256k1,
    psbt::{self},
    secp256k1::{self},
    sighash::{self, SighashCache},
    taproot::{self, LeafVersion},
    transaction, Address, Amount, OutPoint, PrivateKey, Psbt, PublicKey, TapLeafHash,
    TapSighashType, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey,
};
use bitcoin_hashes::Hash;
use hex::FromHex;
use miniscript::{
    psbt::PsbtExt, DefiniteDescriptorKey, Descriptor, DescriptorPublicKey, ToPublicKey,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

const PRIVS: [&str; 10] = ["g", "g", "e", "z", "n", "o", "r", "e", ":)", "x)"];

const SPENDING_ADDRESS: &str = "bc1qtyjhutpk3qhn7z5ucyuwygfgthg6d5zxxya3jy";

#[tokio::main]
async fn main() {
    let descriptor_string = "tr([b8532cd3/86'/0'/0']xpub6BfL2ScBEmCaMfKznDPV2xx4FMKnV5FQhxPn1r2YUQGyDo6SMqiYa8dbxBER9PP8gPJxFxeFRZy1r8yUcEbVZEjzzeX62o2iTYPrQjL5BUr/0/0,{and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:pk(023e66ec249a1332b90b33b6f352bdbec339f17e0b3d9aec8db5f5ad068df286d1),pk(03a4b77e704f075227a655cce9b0639cc21cd6c0da45c29c9e9167b85362bc2d2a)),pk(025de22a16f2d647b2939ac8fd5220b51d0ccc6e9f9f7155584bcbc04c1376de17)),pk(0383835dbe036944f18783e0a525babe23965a2b4fdeca2d2d84997fc6ff0fb06a)),pk(0269d09412514a940f4e07e55edc529d5486d36b715fce59942c7b6d12cc592803)),pk(02a7060f90e50ccebe2b0fef15631760310ec01b0bcc001f4df2bb3dceda08b373)),pk(03a3fdb57da9a5cacbcf636e56260d8f3bb09bd8d0b8bba6a3252c52eff16e4f02)),pk(0294158f38b0c867466024235df60770970c81733f9ce3f74bf38e7e7c655b8bd6)),pk(02ad0c40157f34da06b87c3765bfd3e84a6ba994b4933fdddf0eb4aed49abf45be)),pk(031f4070093d14e3d6fde3f90de77f65b5d484f9e4cd2b0808e545329cf1e5eb49)),and_v(v:and_v(v:sha256(2db9cdb5e102541f19b455fa798e0cb009f5faa6358b9d3507858caf797bca41),ripemd160(8d60757ec290d055be92da400cff617b0423cb14)),after(1729692000))),{{and_v(v:multi_a(8,033f8d10effd74390ab9a99c146421120fa079e1eed4e04da7ed9ee738f31aa27b,022fb7518194c88a56a20814822d367c403fcaa4264c2c42140c2609c9d7e8b724,021b61aa082c8bf45b744be29dd2330b33de9d5095e0986c79d047e43c1bf9abe0,02bfd8c3da227b2a9a853249ba7b65c84e55c29f16a08ad9666c86772011781472,03fea53e5f44d18bf1f3fd812a1f6716ddcd4f6269f6494ac2f2709608fab05cd1,03a8fc10e8ab5e913ba7bdf745624aa5e18f20886d3d5e1134488f7d557e315ed8,03ccce43fa270cd1915cc4ab69dda5764bb6bb899ddba00bcee12acd2ae6beee90,02c3caed276694bcbc0c2e332a1c995103d9900b6bb1fc3daaef735b4dc5df1c74,020ed02089a09973de92ec174c8d04a4426a458e964eb5d2076b9cdb6b3b120af9),and_v(v:and_v(v:pk(02f2f65202a1baa43441bcb3113aaa634a403ad0062dbd05b5fff7e4be7bc6330e),sha256(2db9cdb5e102541f19b455fa798e0cb009f5faa6358b9d3507858caf797bca41)),after(1729819800))),and_v(v:multi_a(4,0211e5ad4b75b2a7960a9f6b25ee4170f9ca29e0517438ede42af56b26015e498d,022b5152f6f094db01f456abc4c6783352394f29cf4be31b7ad360a776a4897a26,02d577314415867e0a73f2261f232e6efd4c0b36a235a792db990a04d421e40420,0354d93a3d4ae0494f421903cbddcfc140d8d98387c4c08003d66838887c2777f0,030935038d9bf80f5e6faeaabe0fff7bba418b57acfe855f089e76ee1485276a41,02d5610246984e9c23cbc7b3135a49eb9c9a710bcbf0e3ad30d2ea570684cf71d9,0298e16a8ff08eefe06963c5401c488c3c45a2f8f8b3219672e3a573ee109d645e,02f6c25034f506e35770797439fce70efe5cfc7181556b941e892e7a5ceb15b24e),and_v(or_c(pk(02ac297d82957d7535dc7e0c289b7f8af8a9ca763cef90d9b74cce413de9930328),v:pk(032aa69b68b400cb8cc1526e84409fef593edf403a6844195eb5dc146358f0f9c9)),and_v(v:and_v(v:and_v(v:pk(02c4daee9ba17b370c19db40fa5bffb12a65b062824e436d3ca303f47a6d35f2ae),pk(034276db1da837a0bcf7651260b1e6e05e44f3349bf97d734a1785f86e979a21f1)),ripemd160(8d60757ec290d055be92da400cff617b0423cb14)),after(1729819800))))},{{and_v(v:multi_a(4,03f85f136a388a53b70ed949eb7db4c41d675cecaaa0980c3e60a26269b77560b7,03bd828ed0af2af77682f6d22c8a55237291c817a517e4b41af14e52b6d3846936,021e5295adc447aec6059c051eba6953b726de2cfcdcc945e5ff6c65fce385ada9,0245a699b81c835daf3f12851b5702043deb6c5e2240c031b696cc9b70d770fe87,036076ba3999b16ba41d2675d1d3f4a8051aab949887444029edebc084c73cac23,03e3f47bee199c76573d57aa8ca494ddc0a838ef834677cf899ef28de71f596672,03884bc1d1e5744e01570d8fa1abc009027441cb17332161dbab482db6603610d2,032726ecfa32259a6a929d22381d84bf874a66569256de7fed6eeff37debec765e),and_v(v:and_v(v:and_v(v:and_v(v:pk(0246ead44b9fad558c37bc86f83a058e5e74aae1d690812867500b7fe4f93f18ad),pk(037d6079e6a1e0b3994ccde1c144ee4735347749de21f1b2c4c2efd22aa95d9945)),pk(023ab01b275717a4a19202a55370e0a3369fc5a7b3570b71d4d8e0bad9a2e43d92)),ripemd160(8d60757ec290d055be92da400cff617b0423cb14)),after(1729877400))),and_v(v:multi_a(4,03647fe46f888c25e34c6ac8cbce6ab43b84675fc1032279735fe25f5833535a86,03e7eb2d27fd6be76fecc14cd9960d3ab944d6a20756c438926da961d657db287b,029b67f5cdf745dba7ceb62d79ab787e65e5c0a672584b12b436b897f22a725fe0,02372cf9647b6df844faf845508efcc63f9565eaebee3a636833087537bcf6afde,0225d8ae1b1269665cc3ce95a502756a271147eb16ea454ac6666007eae28d96b7,022fc55641dcd4e419222e6729cf47cdc9f077e82ced0cbfbd0db3c147eee73be1,02719a5dfdbeefe3fd45c1fec0c42718a9184cac48ce6250c9ddef0e93f476adde,02cae2159edacece609f107591737eb8c0d00b7f80854f94a54d8a84ffee04543a),and_v(v:and_v(v:and_v(v:and_v(v:pk(03b0e7ede035b0b4af243d5bee6751b9a1dceca14a73387afac70d3d429b00354f),pk(0325ce14ca57cdd9e8de60817119ae6f95de4bacb96bd2fae129e94ea5bd51d0b5)),pk(0347980038460a87ecd59776d833ff54578956b0d39255dd2412b783848463a113)),ripemd160(8d60757ec290d055be92da400cff617b0423cb14)),after(1729877400)))},{{and_v(v:multi_a(10,03c44975130f7641a0b870ca3c8f36424fba334a38b280dc6284f4a79a2f657f33,0235c2d78cb2891359e8b5a311213a072686852123558e1f4280bd5aa343b1762d,03bc51f4407e8ed6c3cfd3fe3fbfd1d06b90d1b1038eb68efb8791ecdad92f41bf,03e2b769c928e9a97dc91a05c424397a334851ad91c43202224f7c03087b4bbdaf,02f3614346da2271264cd3aa747a17adcfc2d0db5eb38e02d37239f889a66e5e5c,02e09d829732aa2f703990bd165c3339591bd9f3ffd9953bafa4e0846a582e92c6,02482f4cc68ae926990e5f68820167da861385b8aad1c153c674f9a77eec5229aa,037c18fe4f2e433df0dcc0a090147f61b723c40da456d878ce2a26d6564cf918af,0242b9baf0b071bc217da3c07fe25ab0f33de500da791810b3d329aed003fa1e19,02810f45212c696acace695fa81de9938c4317aa439b57391d48087dc503717242,0369c41f0777a7eb0af3db552e6239012319de363ce8e87e4e878ee4f9e8bfd807,035776bf9b7e6769f7ba9003dda584ffcfb801b7e4b2537abd79aff5ea9d2be66b),after(1729942200)),and_v(v:multi_a(9,03d1d11b1e38db4fa6fc3e95fb929ad941c71cb1d65ab6041280a32f1ef7917035,031b821456510cf8688eb6c6f5a7b3a96151a342e48e3923791d706693c0e53bb3,0287782053235db168a6cd2c30ef079c842fbc1dee68f33c134942810ed9a4c8b5,03922b9ea3b5578efd75c79dbb8a491a4b20bedf9aeaf34bce07c0b157fd26540c,02e8c42a240df0e5f93ecb88f3cd274744e6d7475f5104377cf3ccb0bbc80e0236,021dd08802320387fd5ab136805c50705ee372309594111d342fef9e43516621d9,021dc26a159a691868381a05b0f409247889683f7b81243e26b1c62e90bca29d69,024965ac4a774da0bcc27d2796a68572b98b5749cf9fded16e945367171c3b2fad,029fa277e3f3e13cb66cf7916ab3d853a5442e4e5a3ef65535134085b8874a3cc6,035f3fcb2d81be12e8200b74e5a30c99ba81c89d77295182bb6df07b7a4a83bdec,0348dce598e02ad09b17563d33130905f2cb3433d1196bafac7e75b60a57b7eb37,02012cc8108a9f1ca6f8cf8c269b7939e89edf957e2a5e6153d5d148f9b25bc931),and_v(v:sha256(2db9cdb5e102541f19b455fa798e0cb009f5faa6358b9d3507858caf797bca41),after(1729942200)))},{and_v(v:multi_a(6,0258a150f622fb36f9b0d8fcb26cff9de61998aff8e8152abb46b27f0771ab9e16,03b83c38208c1eb66ff4a392c742ad8ffe50fe48e326f84d2f8054c82f13c0a664,0275ea5643c97c03de2d0936811291637599ca15ef011a8102075f49425d920179,02417dbbd9b6218f7ff74bc9e14052233d9c49c3538e31f29dedb501062f8edb92,03fa20197dcd2f90f7b453b7e498f5d98d92f1b1ae7608611e902aa83324a62262,03174129210960856e85fb8b1859ecfb5f38bd82a1e63df4cd2261ea4391c04096,03437c22bd0e7cbcb3d266eb77702a72110b791cd3fe75831697145352aa5a1337,036c03bec77d0eed7ece017ad99acc2fb4ed345dffe7754075ec06aaa2ff480002),and_v(v:and_v(v:and_v(v:pk(025c3ddc900d5c48c49d13f42ef27ef8819062940ff347a1a4cc3a48671826f2e7),pk(03e83a5ef0a414ecbfe46b0311efe8bfbaa605d12eb4f0ffff94987e635b86d396)),sha256(2db9cdb5e102541f19b455fa798e0cb009f5faa6358b9d3507858caf797bca41)),after(1729877400))),and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:and_v(v:pk(02f482ba919cd4e39d8c163f980c8c6faf86de6bc3750cb3dbeff47786ab11a352),pk(02abdc5564ddbd4295a4b0da1ee4d71326af2ef4452472e00e62561ed8eab6102f)),pk(02a14b893455afe08bb0fea21c18fbe3c09042d540b900c41088e3b8fc6ef117b8)),pk(03519d2bef8cfc585fb00bd73eb323ead75390cc9c085a68b1d87a845fcfbdbb45)),pk(02bc5245f31c696657d8325c1b04e75c3769f67de79613b22f9beb05bfc8b26cf3)),pk(022960cc09036816718ae2b8859f4dbce8a112889e13f3f91cd43fc136fc24ada3)),pk(02f6c882d989bf57c97377b5943ddab71e778fd5ff24582e7f696f5985ebcc4814)),pk(02dff76617c25d2f29800996919e7e3e87ba28e16b953bc798563006d08713f7dd)),pk(033648bc5628c12651451ba29891bd272abe10aaf267772493f36843a6990f5edc)),pk(02d6dd74b20e0506484a07085d7c12c310d8a43b65fa6dcdf6f7b60ace0a453c54)),pk(02e2e24e295b465a6a5b6e962c1634a149503caf8acca3153e2b146c83cacd2064)),pk(035cb3deba66b8f881d2e6979b6bd9a2c049c432ba5c7e625534f7ea8dc10f5d86)),sha256(2db9cdb5e102541f19b455fa798e0cb009f5faa6358b9d3507858caf797bca41)),ripemd160(8d60757ec290d055be92da400cff617b0423cb14))}}}}})#xp6qtaaa";

    let range_descriptor = Descriptor::<DescriptorPublicKey>::from_str(descriptor_string).unwrap();

    let secp = secp256k1::Secp256k1::new();

    let descriptor = range_descriptor.derived_descriptor(&secp, 0).unwrap();

    let tree_of_horror_address =
        Address::from_str("bc1pa8kr5ph0drh7e4e9ylygvcl6ycfnum2rkn96la6ympsc2a2xys0qt0tdl6")
            .unwrap()
            .require_network(bitcoin::Network::Bitcoin)
            .unwrap();

    assert_eq!(
        descriptor.address(bitcoin::Network::Bitcoin).unwrap(),
        tree_of_horror_address
    );

    let res_utxo = reqwest::get(&format!(
        "https://mempool.space/api/address/{}/utxo",
        tree_of_horror_address
    ))
    .await
    .unwrap()
    .text()
    .await
    .unwrap();

    let utxos: Vec<Utxo> = serde_json::from_str(&res_utxo).expect("Failed to parse JSON");

    let sequence = bitcoin::Sequence(0xfffffffe);

    let inputs: Vec<TxIn> = utxos
        .iter()
        .map(|utxo| TxIn {
            previous_output: OutPoint::new(
                Txid::from_str(&utxo.txid).expect("Invalid txid format"),
                utxo.vout,
            ),
            sequence,
            ..Default::default()
        })
        .collect();

    let mut prev_tx = Vec::new();
    for input in inputs.clone() {
        let url = format!(
            "https://mempool.space/api/tx/{}/hex",
            input.previous_output.txid
        );
        let response = reqwest::get(&url).await.unwrap().text().await.unwrap();
        let tx: Transaction = deserialize(&Vec::<u8>::from_hex(&response).unwrap()).unwrap();

        let mut outpoint: Option<OutPoint> = None;
        for (i, out) in tx.output.iter().enumerate() {
            if tree_of_horror_address.script_pubkey() == out.script_pubkey {
                outpoint = Some(OutPoint::new(tx.compute_txid(), i as u32));

                break;
            }
        }
        let prevout = outpoint.expect("Outpoint must exist in tx");

        prev_tx.push(tx.output[prevout.vout as usize].clone());
    }

    let fee = 1337;

    let mut spend_vec = Vec::new();

    let total_amount = utxos.iter().map(|utxo| utxo.value).sum::<u64>();

    spend_vec.push(TxOut {
        value: Amount::from_sat(total_amount - fee),
        script_pubkey: Address::from_str(SPENDING_ADDRESS)
            .unwrap()
            .require_network(bitcoin::Network::Bitcoin)
            .unwrap()
            .script_pubkey(),
    });

    let mut psbt = Psbt {
        unsigned_tx: Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::from_consensus(1729942200),
            input: inputs.clone(),
            output: spend_vec,
        },
        unknown: BTreeMap::new(),
        proprietary: BTreeMap::new(),
        xpub: BTreeMap::new(),
        version: 0,
        inputs: vec![],
        outputs: vec![],
    };

    let input = psbt::Input {
        witness_utxo: Some(prev_tx[0].clone()),

        ..Default::default()
    };

    let (x_only_pks, xonly_keypairs) = wifs_to_xonly_pub_keys(PRIVS.to_vec());

    let desc = Descriptor::<DefiniteDescriptorKey>::from_str(descriptor_string).unwrap();

    psbt.inputs.push(input);
    psbt.outputs.push(psbt::Output::default());

    psbt.update_input_with_descriptor(0, &desc).unwrap();

    let sighash_type = TapSighashType::Default;

    let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);

    let prevouts = sighash::Prevouts::All(&prev_tx);

    if let Descriptor::Tr(ref tr) = descriptor {
        let x_only_keypairs_reqd: Vec<(secp256k1::Keypair, TapLeafHash)> = tr
            .iter_scripts()
            .flat_map(|(_depth, ms)| {
                let leaf_hash = TapLeafHash::from_script(&ms.encode(), LeafVersion::TapScript);

                println!("Leaf hash: {:?}", leaf_hash);

                ms.iter_pk().filter_map({
                    let x_only_pks = x_only_pks.clone();
                    {
                        let xonly_keypairs = xonly_keypairs.clone();

                        move |pk: PublicKey| {
                            let i = x_only_pks
                                .iter()
                                .position(|&x| x.to_x_only_pubkey() == pk.into());

                            match i {
                                Some(idx) => {
                                    println!("Index found: {}", idx);
                                    println!("Key: {:?}", xonly_keypairs[idx].x_only_public_key());
                                    Some((xonly_keypairs[idx], leaf_hash))
                                }
                                None => None,
                            }
                        }
                    }
                })
            })
            .collect();

        for (keypair, leaf_hash) in x_only_keypairs_reqd {
            let sighash_msg = sighash_cache
                .taproot_script_spend_signature_hash(0, &prevouts, leaf_hash, sighash_type)
                .unwrap();
            let msg = secp256k1::Message::from_digest(*sighash_msg.as_byte_array());
            let mut aux_rand = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut aux_rand);
            let signature = secp.sign_schnorr_with_aux_rand(&msg, &keypair, &aux_rand);
            let x_only_pk = x_only_pks[xonly_keypairs.iter().position(|&x| x == keypair).unwrap()];

            secp.verify_schnorr(&signature, &msg, &x_only_pk).unwrap();
            psbt.inputs[0].tap_script_sigs.insert(
                (x_only_pk, leaf_hash),
                taproot::Signature {
                    signature,
                    sighash_type,
                },
            );
        }
    }

    psbt.finalize_mut(&secp).unwrap();
    let tx = psbt.extract(&secp).unwrap();

    let tx = serialize(&tx);

    println!("TX: {}", hex::encode(tx));
}

#[derive(Debug, Serialize, Deserialize)]
struct Utxo {
    txid: String,
    vout: u32,
    status: UtxoStatus,
    value: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct UtxoStatus {
    confirmed: bool,
    block_height: Option<u64>,
    block_hash: Option<String>,
    block_time: Option<u64>,
}

fn wifs_to_xonly_pub_keys(wifs: Vec<&str>) -> (Vec<XOnlyPublicKey>, Vec<secp256k1::Keypair>) {
    let secp = Secp256k1::new();
    let mut x_only_pub_keys = Vec::new();
    let mut x_only_keypairs = Vec::new();

    for wif in wifs {
        let priv_key = PrivateKey::from_wif(wif).expect("Invalid WIF format");
        let secret_key = priv_key.inner;

        let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret_key);
        x_only_keypairs.push(keypair);
        let (x_only_pub_key, _parity) = XOnlyPublicKey::from_keypair(&keypair);

        x_only_pub_keys.push(x_only_pub_key);
    }

    (x_only_pub_keys, x_only_keypairs)
}
