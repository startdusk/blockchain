package database

import (
	"errors"

	"github.com/startdusk/blockchain/foundation/blockchain/merkle"
)

// ErrChainForked is returned from validateNextBlock if another node's chain
// is two or more blocks ahead of ours.
var ErrChainForked = errors.New("blockchain forked, start resync")

// =============================================================================

// BlockData represents what can be serialized to disk and over the network.
type BlockData struct {
	Hash   string      `json:"hash"`
	Header BlockHeader `json:"block"`
	Trans  []BlockTx   `json:"trans"`
}

// =============================================================================

// BlockHeader represents common information required for each block.
type BlockHeader struct {
	Number        uint64    `json:"number"`          // Ethereum: Block number in the chain.
	PrevBlockHash string    `json:"prev_block_hash"` // Bitcoin: Hash of the previous block in the chain.
	TimeStamp     uint64    `json:"timestamp"`       // Bitcoin: Time the block was mined.
	BeneficiaryID AccountID `json:"beneficiary"`     // Ethereum: The account who is receiving fees and tips.
	Difficulty    uint16    `json:"difficulty"`      // Ethereum: Number of 0's needed to solve the hash solution.
	MiningReward  uint64    `json:"mining_reward"`   // Ethereum: The reward for mining this block.
	StateRoot     string    `json:"state_root"`      // Ethereum: Represents a hash of the accounts and their balances.
	TransRoot     string    `json:"trans_root"`      // Both: Represents the merkle tree root hash for the transactions in this block.
	Nonce         uint64    `json:"nonce"`           // Both: Value identified to solve the hash solution.
}

// Block represents a group of transactions batched together.
type Block struct {
	Header     BlockHeader
	MerkleTree *merkle.Tree[BlockTx]
}
