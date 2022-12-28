package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
)

// ZeroHash represents a hash code of zeros.
const ZeroHash string = "0x0000000000000000000000000000000000000000000000000000000000000000"

// startduskID is an arbitrary number for signing messages. This will make it
// clear that the signature comes from the Startdusk blockchain.
// Ethereum and Bitcoin do this as well, but they use the value of 27.
const startduskID = 29

// =============================================================================

// Hash returns a unique string for the value.
func Hash(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return ZeroHash
	}

	hash := sha256.Sum256(data)
	return "0x" + hex.EncodeToString(hash[:])
}

// Sign uses the specified private key to sign the user transaction.
func Sign(value any, privateKey *ecdsa.PrivateKey) (v, r, s *big.Int, err error) {

	// Prepare the transaction for signing.
	data, err := stamp(value)
	if err != nil {
		return nil, nil, nil, err
	}

	// Sign the hash with the private key to produce a signature.
	sig, err := crypto.Sign(data, privateKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// Extract the public key from the data and the signature.
	publicKey, err := crypto.SigToPub(data, sig)
	if err != nil {
		return nil, nil, nil, err
	}

	// Check the public key extracted from the data and signature.
	rs := sig[:crypto.RecoveryIDOffset]
	if !crypto.VerifySignature(crypto.FromECDSAPub(publicKey), data, rs) {
		return nil, nil, nil, errors.New("invalid signature")
	}

	// Convert the 65 byte signature into the [R|S|V] format.
	v, r, s = ToSignatureValues(sig)

	return v, r, s, nil
}

// VerifySignature verifies the signature conforms to our standards and
// is associated with the data claimed to be signed.
func VerifySignature(value any, v, r, s *big.Int) error {

	// Check the recovery id is either 0 or 1.
	uintV := v.Uint64() - startduskID
	if uintV != 0 && uintV != 1 {
		return errors.New("invalid recovery id")
	}

	// Check the signature values are valid.
	if !crypto.ValidateSignatureValues(byte(uintV), r, s, false) {
		return errors.New("invalid signature values")
	}

	// Prepare the transaction for recovery and validation.
	tran, err := stamp(value)
	if err != nil {
		return err
	}

	// Convert the [R|S|V] format into the original 65 bytes.
	sig := ToSignatureBytes(v, r, s)

	// Capture the uncompressed public key associated with this signature.
	sigPublicKey, err := crypto.Ecrecover(tran, sig)
	if err != nil {
		return fmt.Errorf("ecrecover, %w", err)
	}

	// Check that the given public key created the signature over the data.
	rs := sig[:crypto.RecoveryIDOffset]
	if !crypto.VerifySignature(sigPublicKey, tran, rs) {
		return errors.New("invalid signature")
	}

	return nil
}

// FromAddress extracts the address for the account that signed the transaction.
func FromAddress(value any, v, r, s *big.Int) (string, error) {

	// Prepare the transaction for public key extraction.
	tran, err := stamp(value)
	if err != nil {
		return "", err
	}

	// Convert the [R|S|V] format into the original 65 bytes.
	sig := ToSignatureBytes(v, r, s)

	// Validate the signature since there can be conversion issues
	// between [R|S|V] to []bytes. Leading 0's are truncated by big package.
	var sigPublicKey []byte
	{
		sigPublicKey, err = crypto.Ecrecover(tran, sig)
		if err != nil {
			return "", err
		}

		rs := sig[:crypto.RecoveryIDOffset]
		if !crypto.VerifySignature(sigPublicKey, tran, rs) {
			return "", errors.New("invalid signature")
		}
	}

	// Capture the public key associated with this signature.
	x, y := elliptic.Unmarshal(crypto.S256(), sigPublicKey)
	publicKey := ecdsa.PublicKey{Curve: crypto.S256(), X: x, Y: y}

	// Extract the account address from the public key.
	return crypto.PubkeyToAddress(publicKey).String(), nil
}

// SignatureString returns the signature as a string.
func SignatureString(v, r, s *big.Int) string {
	return "0x" + hex.EncodeToString(toSignatureBytesWithStartduskID(v, r, s))
}

// =============================================================================

// stamp returns a hash of 32 bytes that represents this user
// transaction with the Startdusk stamp embedded into the final hash.
func stamp(value any) ([]byte, error) {

	// Marshal the data.
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	// Hash the transaction data into a 32 byte array. This will provide
	// a data length consistency with all transactions.
	txHash := crypto.Keccak256Hash(data)

	// Convert the stamp into a slice of bytes. This stamp is
	// used so signatures we produce when signing transactions
	// are always unique to the Startdusk blockchain.
	stamp := []byte("\x19Startdusk Signed Message:\n32")

	// Hash the stamp and txHash together in a final 32 byte array
	// that represents the transaction data.
	tran := crypto.Keccak256Hash(stamp, txHash.Bytes())

	return tran.Bytes(), nil
}

// ToSignatureValues converts the signature into the r, s, v values.
func ToSignatureValues(sig []byte) (v, r, s *big.Int) {
	r = new(big.Int).SetBytes(sig[:32])
	s = new(big.Int).SetBytes(sig[32:64])
	v = new(big.Int).SetBytes([]byte{sig[64] + startduskID})

	return v, r, s
}

// ToSignatureBytes converts the r, s, v values into a slice of bytes
// with the removal of the startduskID.
func ToSignatureBytes(v, r, s *big.Int) []byte {
	sig := make([]byte, crypto.SignatureLength)

	rBytes := r.Bytes()
	if len(rBytes) == 31 {
		copy(sig[1:], rBytes)
	} else {
		copy(sig, rBytes)
	}

	sBytes := s.Bytes()
	if len(sBytes) == 31 {
		copy(sig[33:], sBytes)
	} else {
		copy(sig[32:], sBytes)
	}

	sig[64] = byte(v.Uint64() - startduskID)

	return sig
}

// toSignatureBytesWithStartduskID converts the r, s, v values into a slice of bytes
// keeping the Startdusk id.
func toSignatureBytesWithStartduskID(v, r, s *big.Int) []byte {
	sig := ToSignatureBytes(v, r, s)
	sig[64] = byte(v.Uint64())

	return sig
}
