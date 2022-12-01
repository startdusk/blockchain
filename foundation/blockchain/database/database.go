package database

import (
	"sync"

	"github.com/startdusk/blockchain/foundation/blockchain/genesis"
)

// Database manages data related to accounts who have transacted on the blockchain.
type Database struct {
	mu      sync.RWMutex
	genesis genesis.Genesis
	// latestBlock Block
	accounts map[AccountID]Account
}
