package ethsign

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// SignToAddress get *common.Address string from sign.
func SignToAddress(message, sign string) (*common.Address, error) {
	// handle the message
	hash := crypto.Keccak256Hash([]byte(message)).Hex()
	ethSignHash := signHash([]byte(hash))

	// handle sign
	sig, err := hexutil.Decode(sign)
	if err != nil {
		return nil, err
	}
	// https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	if len(sig) != 65 {
		return nil, errors.New("signature must be 65 bytes long")
	}
	if sig[64] != 27 && sig[64] != 28 {
		return nil, errors.New("invalid Ethereum signature (V is not 27 or 28)")
	}
	sig[64] -= 27 // Transform yellow paper V from 27/28 to 0/1

	// get the public key that created the given signature.
	pubKey, err := crypto.SigToPub(ethSignHash, sig)
	if err != nil {
		return nil, err
	}
	// convert public key to address
	addr := crypto.PubkeyToAddress(*pubKey)

	return &addr, nil
}

// SignToAddressHex get address string from sign.
func SignToAddressHex(message, sign string) (string, error) {
	addr, err := SignToAddress(message, sign)
	if err != nil {
		return "", err
	}

	return addr.Hex(), nil
}

// SignVerify verify the sign.
func SignVerify(message, sign string, pubAddr string) (bool, error) {
	addr, err := SignToAddressHex(message, sign)
	if err != nil {
		return false, err
	}

	return strings.ToLower(pubAddr) == strings.ToLower(addr), nil
}

// https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L404
//
// signHash is a helper function that calculates a hash for the given message that can be
// safely used to calculate a signature from.
//
// The hash is calculated as
//   keccak256("\x19Ethereum Signed Message:\n"${message length}${message}).
//
// This gives context to the signed message and prevents signing of transactions.
func signHash(data []byte) []byte {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(msg))
}
