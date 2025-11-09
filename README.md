# Blace Backend Architecture

## System Overview

The Blace backend system implements a blockchain-based architecture with the following key components and workflows:

## Core Components

### 1. JSON RPC Interface
- Receives transactions and forwards them to the mempool
- Handles incoming transaction requests from clients

### 2. Mempool Management
- Stores pending transactions before they are processed
- Acts as a transaction queue for the system

### 3. Block Production Loop (1-second interval)
- Processes transactions from the mempool for the latest block
- Calculates new Merkle Patricia Trie structures
- Computes new state root and transaction root
- Generates new blocks and stores them locally

### 4. Block Finalization Loop (60-second interval)
- Tracks blocks from produced to finalized status
- Identifies all blocks in the finalization chain
- Replays transactions in block order
- Calculates final state root from the produced block

### 5. Zero-Knowledge Proof System
- Integrates with RISC Zero SP1 or similar ZK circuits
- Generates ZK proofs for block validation
- Writes new block hash to Layer 1 or other blockchain
- Includes ZK proof alongside block hash

## Workflow Summary

1. **Transaction Reception**: JSON RPC receives transactions → mempool
2. **Block Production**: 1-second loop processes mempool → new blocks
3. **Block Finalization**: 60-second loop finalizes blocks → state calculation
4. **ZK Proof Generation**: Circuit processes finalized state → proof generation
5. **Layer 1 Integration**: Block hash + ZK proof → main blockchain

## Technical Architecture

- **Blockchain Layer**: Custom blockchain with mempool and block production
- **State Management**: Merkle Patricia Trie for efficient state storage
- **Consensus**: Block production and finalization mechanisms
- **ZK Integration**: RISC Zero SP1 or equivalent for proof generation
- **Cross-chain**: Integration with Layer 1 and other blockchains
