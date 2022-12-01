package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	err := sign()
	if err != nil {
		log.Fatalln(err)
	}
}

func sign() error {
	path := fmt.Sprintf("%s%s.ecdsa", "zblock/accounts/", "ed")
	privateKey, err := crypto.LoadECDSA(path)
	if err != nil {
		return err
	}

	address := crypto.PubkeyToAddress(privateKey.PublicKey).String()
	fmt.Println(address)

	v := struct {
		Name string
	}{
		Name: "startdusk",
	}

	data, err := stamp(v)
	if err != nil {
		return fmt.Errorf("stamp: %w", err)
	}

	// Sign the hash with the private key to produce a signature.
	sig, err := crypto.Sign(data, privateKey)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	fmt.Println("SIG: ", sig)

	// =========================================================================

	v2 := struct {
		Name string
	}{
		Name: "startdusk",
	}
	data2, err := stamp(v2)
	if err != nil {
		return err
	}

	sigPublicKey, err := crypto.Ecrecover(data2, sig)
	if err != nil {
		return err
	}

	// should error
	rs := sig[:crypto.RecoveryIDOffset]
	if !crypto.VerifySignature(sigPublicKey, data2, rs) {
		return errors.New("invalid signature")
	}

	// Capture the public key associated with this signature.
	x, y := elliptic.Unmarshal(crypto.S256(), sigPublicKey)
	publicKey := ecdsa.PublicKey{Curve: crypto.S256(), X: x, Y: y}

	// Extract the account address from the public key.
	parseAddress := crypto.PubkeyToAddress(publicKey).String()
	fmt.Println(parseAddress)
	return nil
}

func stamp(value any) ([]byte, error) {
	// Marshal the value
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	// Hash the transaction data into a 32 byte array. This will private
	// a data length consistency with all transactions.
	txHash := crypto.Keccak256Hash(data)

	// Convert the stamp into a slice of bytes. This stamp is
	// used so signatures we produce when signing transactions
	// are always unique Startdusk blockchain.
	stamp := []byte("\x19Startdusk Signed Message:\n32")

	// Hash the stamp and txHash together in a final 32 byte array
	// that represents the transcation data.
	tran := crypto.Keccak256Hash(stamp, txHash.Bytes())

	return tran.Bytes(), nil
}
