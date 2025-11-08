//! Custom precompile provider implementation.

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
use std::{boxed::Box, io::Read};
use util::{EvmArray, EvmHashmap};
mod util;

pub enum CollectionValue<T: EVMStorable> {
    Array(T),
    Map(T),
}

pub struct EvmStoreValues {
    bytes: Vec<u8>,
    collections: Vec<EvmStoreValues>,
}

pub trait EVMStorable {
    fn encode_store_values(&self) -> EvmStoreValues;
}

#[derive(Debug)]
struct RGBPixel {
    r: u8,
    g: u8,
    b: u8,
}

#[derive(Debug)]
struct Game {
    name: String,
    size: U256,
    grid: Vec<RGBPixel>,
}

impl<T> EVMStorable for Vec<T> {
    fn encode_store_values(&self) -> EvmStoreValues {
        let length = self.len();
        todo!()
    }
}

impl EVMStorable for RGBPixel {
    fn encode_store_values(&self) -> EvmStoreValues {
        todo!()
    }
}

impl EVMStorable for Game {
    fn encode_store_values(&self) -> EvmStoreValues {
        todo!()
    }
}

pub const BLACE_PRECOMPILE_ADDRESS: Address = address!("0000000000000000000000000000000000000000");
sol! {
    interface BlaceContract {
        function create_blace(bytes32 uuid, string memory name, uint256 size) external returns (bytes32 gameId);
        function place_pixel(bytes32 gameId, uint256 x, uint256 y, uint8 r, uint8 g, uint8 b) external returns (bool success);
    }

}

/// Custom precompile provider that includes journal access functionality
#[derive(Debug, Clone)]
pub struct CustomPrecompileProvider {
    inner: EthPrecompiles,
    spec: SpecId,
}

impl CustomPrecompileProvider {
    pub fn new_with_spec(spec: SpecId) -> Self {
        Self {
            inner: EthPrecompiles::default(),
            spec,
        }
    }
}

impl<CTX> PrecompileProvider<CTX> for CustomPrecompileProvider
where
    CTX: ContextTr<Cfg: Cfg<Spec = SpecId>>,
{
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        if spec == self.spec {
            return false;
        }
        self.spec = spec;
        self.inner = EthPrecompiles::default();
        true
    }

    fn run(
        &mut self,
        context: &mut CTX,
        address: &Address,
        inputs: &InputsImpl,
        is_static: bool,
        gas_limit: u64,
    ) -> Result<Option<Self::Output>, String> {
        if *address == BLACE_PRECOMPILE_ADDRESS {
            return Ok(Some(run_custom_precompile(
                context, inputs, is_static, gas_limit,
            )?));
        }
        self.inner
            .run(context, address, inputs, is_static, gas_limit)
    }

    fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
        let mut addresses = vec![BLACE_PRECOMPILE_ADDRESS];
        addresses.extend(self.inner.warm_addresses());
        Box::new(addresses.into_iter())
    }

    fn contains(&self, address: &Address) -> bool {
        *address == BLACE_PRECOMPILE_ADDRESS || self.inner.contains(address)
    }
}

fn run_custom_precompile<CTX: ContextTr>(
    context: &mut CTX,
    inputs: &InputsImpl,
    is_static: bool,
    gas_limit: u64,
) -> Result<InterpreterResult, String> {
    /*
    struct RGBPixel {
        uint8 r;
        uint8 g;
        uint8 b;
    }
    struct game {
    string name
    uint16 size;
    RGBPixel[] grid;
    }

    slot 0
    mapping(uuid=>game)

    slot 1
    games array

    * */
    let input_bytes = match &inputs.input {
        revm::interpreter::CallInput::SharedBuffer(range) => {
            if let Some(slice) = context.local().shared_memory_buffer_slice(range.clone()) {
                slice.to_vec()
            } else {
                vec![]
            }
        }
        revm::interpreter::CallInput::Bytes(bytes) => bytes.0.to_vec(),
    };

    let selector: [u8; 4] = input_bytes[0..4].try_into().unwrap();

    let result: PrecompileResult = match selector {
        BlaceContract::create_blaceCall::SELECTOR => {
            println!("create game with bytes {:?}", input_bytes);
            let call = BlaceContract::create_blaceCall::abi_decode(&input_bytes).unwrap();
            let key = U256::from_be_bytes(<[u8; 32]>::try_from(call.uuid.as_slice()).unwrap());

            //mapping(uuid=>game)
            let hashmap = EvmHashmap::<Game>::new(BLACE_PRECOMPILE_ADDRESS, U256::from(0));

            //uuid[] game_id_array)
            let game_array = EvmArray::<Game>::new(BLACE_PRECOMPILE_ADDRESS, U256::from(1));

            if hashmap.exist(key, context.journal_mut()) {
                Ok(PrecompileOutput::new_reverted(0, Bytes::new()))
            } else {
                let game = Game {
                    name: call.name,
                    size: call.size,
                    grid: vec![],
                };
                // let game_bytes = game.abi_encode_packed();
                // println!("{:?}", game_bytes);
                // println!("{:?}", game);
                // println!("{:?}", game.abi_encoded_size());
                hashmap.insert(key, game, context.journal_mut());

                Ok(PrecompileOutput::new(0, Bytes::new()))
            }
        }
        BlaceContract::place_pixelCall::SELECTOR => {
            println!("create game with bytes {:?}", input_bytes);
            let call = BlaceContract::place_pixelCall::abi_decode(&input_bytes).unwrap();
            // handle_write_storage(context, key,call.(call) gas_limit)
            Err(PrecompileError::Other("Invalid input length".to_string()))
        }
        _ => Err(PrecompileError::Other("Invalid input length".to_string())),
    };

    match result {
        Ok(output) => {
            let mut interpreter_result = InterpreterResult {
                result: if output.reverted {
                    InstructionResult::Revert
                } else {
                    InstructionResult::Return
                },
                gas: Gas::new(gas_limit),
                output: output.bytes,
            };
            let underflow = interpreter_result.gas.record_cost(output.gas_used);
            if !underflow {
                interpreter_result.result = InstructionResult::PrecompileOOG;
            }
            Ok(interpreter_result)
        }
        Err(e) => Ok(InterpreterResult {
            result: if e.is_oog() {
                InstructionResult::PrecompileOOG
            } else {
                InstructionResult::PrecompileError
            },
            gas: Gas::new(gas_limit),
            output: Bytes::new(),
        }),
    }
}
