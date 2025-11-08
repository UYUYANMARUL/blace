use alloy::sol;
use alloy_sol_types::{SolCall, SolValue};
use keccak_hash::{keccak, keccak256};
use revm::{
    context::Cfg,
    context_interface::{ContextTr, JournalTr, LocalContextTr, Transaction},
    handler::{EthPrecompiles, PrecompileProvider},
    interpreter::{Gas, InputsImpl, InstructionResult, InterpreterResult},
    precompile::{PrecompileError, PrecompileOutput, PrecompileResult},
    primitives::{address, hardfork::SpecId, Address, Bytes, U256},
};
use std::string::String;
use std::{boxed::Box, marker::PhantomData};

use super::EVMStorable;

fn bytes_to_u256_vec(data: &[u8]) -> Vec<U256> {
    data.chunks(32)
        .map(|chunk| {
            let mut padded = [0u8; 32];
            let start = 32 - chunk.len();
            padded[start..].copy_from_slice(chunk); // pad on the left (big-endian)
            U256::from_be_bytes(padded)
        })
        .collect()
}

fn string_to_u256_chunks(s: &str) -> (Vec<U256>, usize) {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut chunks = Vec::new();
    for chunk in bytes.chunks(32) {
        let mut buf = [0u8; 32];
        buf[..chunk.len()].copy_from_slice(chunk);
        let val = U256::from_be_bytes(buf);
        chunks.push(val);
    }
    (chunks, len)
}

pub struct EvmHashmap<T: EVMStorable> {
    address: Address,
    slot: U256,
    _phantom: PhantomData<T>,
}

impl<T: EVMStorable> EvmHashmap<T> {
    pub fn new(address: Address, slot: U256) -> Self {
        EvmHashmap {
            address,
            slot,
            _phantom: PhantomData::default(),
        }
    }

    pub fn exist<J: JournalTr>(&self, key: U256, journal: &mut J) -> bool {
        let encoded = (key, self.slot).abi_encode_packed();
        let hash_key = U256::from_be_bytes(keccak(&encoded).0);
        //todo handle error case
        let map_value = journal.sload(self.address, hash_key).unwrap();
        !map_value.is_zero()
    }

    pub fn insert<J: JournalTr>(&self, key: U256, data: T, journal: &mut J) {
        let encoded = (key, self.slot).abi_encode_packed();
        let hash_key = U256::from_be_bytes(keccak(&encoded).0);

        //todo handle error case
        let game_exist = journal.sload(self.address, hash_key).unwrap().is_zero();
        todo!()
    }

    pub fn get() -> T {
        todo!()
    }
}

pub struct EvmArray<T: EVMStorable> {
    address: Address,
    slot: U256,
    _phantom: PhantomData<T>,
}

impl<T: EVMStorable> EvmArray<T> {
    pub fn new(address: Address, slot: U256) -> Self {
        EvmArray {
            address,
            slot,
            _phantom: PhantomData::default(),
        }
    }

    pub fn push<J: JournalTr>(&self, data: T, journal: &mut J) {
        // let array_start_key = U256::from_be_bytes(keccak(self.slot.abi_encode_packed()).0);
        // //todo handle error case
        // let len = journal.sload(self.address, array_start_key).unwrap();
        // let value = data.abi_encode_packed();
        // let data = bytes_to_u256_vec(&value);
        //
        // for x in data {
        //     let new_data_key = len.data + U256::from(1);
        //     println!("{:?} , {:?}", len, new_data_key);
        //     journal.sstore(self.address, array_start_key, x).unwrap();
        // }
    }

    pub fn set(index: U256, data: T) {}

    pub fn get<J: JournalTr>(&self, index: U256, journal: &mut J) -> T {
        let array_start_key = U256::from_be_bytes(keccak(self.slot.abi_encode_packed()).0);
        //todo handle error case
        let len = journal.sload(self.address, array_start_key).unwrap();
        let new_data_key = len.data + U256::from(1) + index;
        let value = journal.sload(self.address, new_data_key).unwrap();

        todo!()
    }

    pub fn len() -> U256 {
        todo!()
    }
}
