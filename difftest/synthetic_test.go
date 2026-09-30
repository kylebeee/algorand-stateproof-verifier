package difftest

// Synthetic proofs from go-algorand's own prover (crypto/stateproof.MakeProver), over shapes the
// chain has not produced: one participant, a handful, thousands; equal, skewed and extreme
// weights; proven weight from barely-reached to almost-all; other strength targets and key
// lifetimes. Each proof, and every structured mutation of it, is compared on both sides.

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return v
	}
	return def
}

type synthConfig struct {
	parts       int
	weights     string // equal | uniform | skewed | huge | ones
	provenFrac  float64
	strength    uint64
	keyLifetime uint64
	signers     int // distinct Falcon key sets
	roundMult   uint64
}

func (c synthConfig) String() string {
	return fmt.Sprintf("p%d-%s-f%.2f-s%d-kl%d-k%d-r%d", c.parts, c.weights, c.provenFrac, c.strength, c.keyLifetime, c.signers, c.roundMult)
}

var signerCache = map[[3]uint64]*merklesignature.Secrets{}

// signer returns key set idx for the given validity. Its keys are derived from (idx, lastValid,
// keyLifetime), so every process builds the same keys and therefore the same proofs.
func signer(t testing.TB, idx int, lastValid, keyLifetime uint64) *merklesignature.Secrets {
	k := [3]uint64{uint64(idx), lastValid, keyLifetime}
	if s, ok := signerCache[k]; ok {
		return s
	}
	var seed [32]byte
	binary.BigEndian.PutUint64(seed[0:], k[0])
	binary.BigEndian.PutUint64(seed[8:], k[1])
	binary.BigEndian.PutUint64(seed[16:], k[2])
	s, err := merklesignature.DiffNewFromSeed(seed, 0, lastValid, keyLifetime)
	if err != nil {
		t.Fatal(err)
	}
	signerCache[k] = s
	return s
}

// makeSynthetic returns a proof built by go-algorand's prover, or nil and the reason if the
// prover declines the configuration (e.g. more reveals than MaxReveals).
func makeSynthetic(t testing.TB, cfg synthConfig, r *rand.Rand) (*Case, string) {
	round := cfg.keyLifetime * cfg.roundMult
	var data stateproof.MessageHash
	r.Read(data[:])

	weights := make([]uint64, cfg.parts)
	for i := range weights {
		switch cfg.weights {
		case "equal":
			weights[i] = 1_000_000
		case "uniform":
			weights[i] = 1 + uint64(r.Int63n(10_000_000))
		case "skewed":
			weights[i] = 1 + uint64(r.ExpFloat64()*1e6)
			if i == 0 {
				weights[i] = uint64(cfg.parts) * 5_000_000 // one whale
			}
		case "huge":
			weights[i] = (1 << 62) / uint64(cfg.parts) / 2
		case "ones":
			weights[i] = 1
		}
	}
	var total uint64
	for _, w := range weights {
		total += w
	}
	proven := uint64(float64(total) * cfg.provenFrac)
	if proven == 0 {
		proven = 1
	}

	secrets := make([]*merklesignature.Secrets, cfg.signers)
	sigs := make([]merklesignature.Signature, cfg.signers)
	for i := range secrets {
		secrets[i] = signer(t, i, round+cfg.keyLifetime, cfg.keyLifetime)
		sig, err := secrets[i].GetSigner(round).SignBytes(data[:])
		if err != nil {
			t.Fatal(err)
		}
		sigs[i] = sig
	}
	parts := make([]basics.Participant, cfg.parts)
	for i := range parts {
		parts[i] = basics.Participant{PK: *secrets[i%cfg.signers].GetVerifier(), Weight: weights[i]}
	}
	partcom, err := merklearray.BuildVectorCommitmentTree(basics.ParticipantsArray(parts), crypto.HashFactory{HashType: stateproof.HashType})
	if err != nil {
		t.Fatal(err)
	}
	b, err := stateproof.MakeProver(data, round, proven, parts, partcom, cfg.strength)
	if err != nil {
		return nil, "MakeProver: " + err.Error()
	}
	// Sign until the signed weight passes a random target above the proven weight: sometimes
	// barely (many reveals), usually comfortably, sometimes everyone.
	target := proven + uint64(float64(total-proven)*[]float64{0.02, 0.3, 0.6, 1}[r.Intn(4)])
	for _, i := range r.Perm(cfg.parts) {
		if b.Ready() && b.SignedWeight() >= target {
			break
		}
		if err := b.Add(uint64(i), sigs[i%cfg.signers]); err != nil {
			t.Fatal(err)
		}
	}
	if !b.Ready() {
		return nil, "not enough weight signed"
	}
	sp, err := b.CreateProof()
	if err != nil {
		return nil, "CreateProof: " + err.Error()
	}
	ln, err := stateproof.LnIntApproximation(proven)
	if err != nil {
		t.Fatal(err)
	}
	return &Case{
		Voters:   partcom.Root(),
		LnPW:     ln,
		Strength: cfg.strength,
		Round:    round,
		MsgHash:  data,
		Proof:    protocol.Encode(sp),
	}, ""
}

func synthConfigs(r *rand.Rand, n int) []synthConfig {
	fixed := []synthConfig{
		{1, "equal", 0.5, 256, 256, 1, 1},
		{2, "equal", 0.3, 256, 256, 1, 1},
		{3, "uniform", 0.9, 256, 256, 2, 2},
		{7, "skewed", 0.3, 256, 256, 3, 1},
		{64, "equal", 0.3, 256, 256, 2, 3},
		{100, "uniform", 0.5, 256, 256, 4, 1},
		{255, "ones", 0.5, 256, 256, 1, 1},
		{256, "uniform", 0.3, 256, 256, 2, 1},
		{257, "skewed", 0.6, 256, 256, 2, 1},
		{1000, "uniform", 0.3, 256, 256, 4, 1},
		{4000, "skewed", 0.3, 256, 256, 3, 1},
		{50, "huge", 0.3, 256, 256, 2, 1},
		{50, "uniform", 0.99, 256, 256, 2, 1},
		{50, "uniform", 0.01, 256, 256, 2, 1},
		{40, "uniform", 0.3, 16, 256, 2, 1},
		{40, "uniform", 0.3, 64, 256, 2, 1},
		{40, "uniform", 0.3, 300, 256, 2, 1},
		{40, "uniform", 0.3, 256, 16, 2, 5},
		{40, "uniform", 0.3, 256, 128, 2, 3},
		{40, "uniform", 0.3, 256, 1, 2, 7},
	}
	out := append([]synthConfig(nil), fixed...)
	schemes := []string{"equal", "uniform", "skewed", "huge", "ones"}
	lifetimes := []uint64{256, 256, 256, 128, 64, 16}
	strengths := []uint64{256, 256, 256, 32, 128, 512}
	for len(out) < n {
		out = append(out, synthConfig{
			parts:       1 + r.Intn(600),
			weights:     schemes[r.Intn(len(schemes))],
			provenFrac:  0.05 + r.Float64()*0.9,
			strength:    strengths[r.Intn(len(strengths))],
			keyLifetime: lifetimes[r.Intn(len(lifetimes))],
			signers:     1 + r.Intn(3),
			roundMult:   1 + uint64(r.Intn(4)),
		})
	}
	return out
}

func TestSyntheticProofs(t *testing.T) {
	r := rand.New(rand.NewSource(int64(envInt("DIFFTEST_SEED", 1))))
	n := envInt("DIFFTEST_SYNTH", 60)
	draws := envInt("DIFFTEST_DRAWS", 3)
	made := 0
	for _, cfg := range synthConfigs(r, n) {
		c, why := makeSynthetic(t, cfg, r)
		if c == nil {
			t.Logf("prover declined %s: %s", cfg, why)
			continue
		}
		made++
		g, rs := CompareCase(t, "synthetic", cfg.String(), c)
		if g.Status != Accepted {
			t.Errorf("%s: go-algorand rejects its own proof: %s", cfg, g.Err)
		}
		_ = rs
		mutateAndCompare(t, "synthetic", cfg.String(), c, draws, r.Int63())
	}
	t.Logf("%d synthetic proofs", made)
}
