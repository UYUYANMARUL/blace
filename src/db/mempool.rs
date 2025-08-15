use alloy::consensus::TypedTransaction;
use std::collections::HashMap;

pub struct Mempool {
    db: HashMap<String, TypedTransaction>,
}

impl Mempool {
    pub fn new() -> Self {
        Self { db: HashMap::new() }
    }

    pub fn add_transaction_to_mempool(&mut self, key: String, value: TypedTransaction) {
        self.db.insert(key, value);
    }

    pub fn remove_transaction_from_mempool(&mut self, key: String) {
        self.db.remove(&key);
    }
}
