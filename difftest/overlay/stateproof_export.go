// Added to go-algorand's crypto/stateproof package at build time through `go test -overlay`
// (see run.sh), so the tests can call its unexported weight and coin logic. The reference
// sources themselves are not modified.

package stateproof

import "github.com/algorand/go-algorand/crypto"

// DiffVerifyWeights is verifyWeights.
func DiffVerifyWeights(signedWeight, lnProvenWeight, numOfReveals, strengthTarget uint64) error {
	return verifyWeights(signedWeight, lnProvenWeight, numOfReveals, strengthTarget)
}

// DiffCoins returns the first n coins, seeded exactly as Verifier.Verify seeds them.
func DiffCoins(partCommitment crypto.GenericDigest, lnProvenWeight uint64, sigCommitment crypto.GenericDigest, signedWeight uint64, data MessageHash, n int) []uint64 {
	choice := coinChoiceSeed{
		partCommitment: partCommitment,
		lnProvenWeight: lnProvenWeight,
		sigCommitment:  sigCommitment,
		signedWeight:   signedWeight,
		data:           data,
	}
	g := makeCoinGenerator(&choice)
	out := make([]uint64, n)
	for i := range out {
		out[i] = g.getNextCoin()
	}
	return out
}
