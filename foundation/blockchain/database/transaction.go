package database

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/startdusk/blockchain/foundation/blockchain/signature"
)

// =============================================================================

// Tx is the transactional information between two parties.
type Tx struct {
	ChainID uint16    `json:"chain_id"` // The chain id that is listed in the genesis.
	ToID    AccountID `json:"to"`       // Account receiving the benefit of the transaction.
	Nonce   uint64    `json:"nonce"`    // Unique id for the transaction supplied by the user.
	Value   uint64    `json:"value"`    // Monetary value received from this transaction.
	Tip     uint64    `json:"tip"`      // Tip offered by the sender as an incentive to mine this transaction.
	Data    []byte    `json:"data"`     // Extra data related to the transaction.
}

// NewTx constructs a new transaction.
func NewTx(chainID uint16, nonce uint64, toID AccountID, value uint64, tip uint64, data []byte) (Tx, error) {
	if !toID.IsAccountID() {
		return Tx{}, fmt.Errorf("to account is not property formatted")
	}

	tx := Tx{
		ChainID: chainID,
		ToID:    toID,
		Nonce:   nonce,
		Value:   value,
		Tip:     tip,
		Data:    data,
	}

	return tx, nil
}

// =============================================================================

// Sign uses the specified private key to sign the transaction.
func (tx Tx) Sign(privateKey *ecdsa.PrivateKey) (SignedTx, error) {
	// Validate the to account address is a valid address.
	if !tx.ToID.IsAccountID() {
		return SignedTx{}, fmt.Errorf("to account is not properly formatted")
	}

	// Sign the transaction with the private key to produce a signature.
	v, r, s, err := signature.Sign(tx, privateKey)
	if err != nil {
		return SignedTx{}, err
	}

	// Construct the signed transaction by adding the signature
	// in the [R|S|V] foramt.
	signedTx := SignedTx{
		Tx: tx,
		V:  v,
		R:  r,
		S:  s,
	}

	return signedTx, nil
}

// =============================================================================

// SignedTx is a signed version of the transaction. This is how clients like
// a wallet provide transactions for inclusion into the blockchain
type SignedTx struct {
	Tx
	V *big.Int `json:"v"` // Recovery indentifier, either 29 or 30 with startduskID.
	R *big.Int `json:"r"` // First coordinate of the ECDSA signature.
	S *big.Int `json:"s"` // Second coordinate of the ECDSA signature.
}

// Validate verifies the transaction has a proper signature that conforms to our
// standards and is associated with the data claimed to be signed. It also
// checks the format of the to acount.
func (tx SignedTx) Validate() error {
	if !tx.ToID.IsAccountID() {
		return errors.New("invalid account for to account")
	}

	return signature.VerifySignature(tx.Tx, tx.V, tx.R, tx.S)
}

// FromAccount extracts the account id that signed the transaction.
func (tx SignedTx) FromAccount() (AccountID, error) {
	address, err := signature.FromAddress(tx.Tx, tx.V, tx.R, tx.S)
	return AccountID(address), err
}
