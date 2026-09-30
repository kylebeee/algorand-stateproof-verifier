// Added to go-algorand's crypto/merklesignature package at build time through `go test -overlay`
// (see run.sh), so synthetic proofs can be rebuilt identically in every process. The reference
// sources themselves are not modified.

package merklesignature

import (
	"encoding/binary"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
)

// DiffNewFromSeed is New with each ephemeral Falcon key generated from a seed derived from
// seed and the key's index, instead of fresh randomness.
func DiffNewFromSeed(seed [32]byte, firstValid, lastValid, keyLifetime uint64) (*Secrets, error) {
	if firstValid > lastValid {
		return nil, ErrStartBiggerThanEndRound
	}
	if keyLifetime == 0 {
		return nil, ErrKeyLifetimeIsZero
	}
	numberOfKeys := lastValid/keyLifetime - ((firstValid - 1) / keyLifetime)
	if firstValid == 0 {
		numberOfKeys = lastValid/keyLifetime + 1
	}
	keys := make([]crypto.FalconSigner, numberOfKeys)
	for i := range keys {
		buf := append(seed[:], make([]byte, 8)...)
		binary.BigEndian.PutUint64(buf[32:], uint64(i))
		k, err := crypto.GenerateFalconSigner(crypto.FalconSeed(crypto.Hash(buf)))
		if err != nil {
			return nil, err
		}
		keys[i] = k
	}
	tree, err := merklearray.BuildVectorCommitmentTree(&committablePublicKeyArray{keys, firstValid, keyLifetime}, crypto.HashFactory{HashType: MerkleSignatureSchemeHashFunction})
	if err != nil {
		return nil, err
	}
	return &Secrets{
		ephemeralKeys: keys,
		SignerContext: SignerContext{
			FirstValid:  firstValid,
			KeyLifetime: keyLifetime,
			Tree:        *tree,
		},
	}, nil
}
