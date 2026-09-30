package difftest

// Coverage-guided fuzzing (go test -fuzz). Seeds are real and synthetic proofs; the fuzzer
// explores from there. Any divergence fails and is saved under findings/ and testdata/fuzz/.
//
//	./run.sh -run '^$' -fuzz FuzzStateProofBytes -fuzztime 30m

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/protocol"
)

var (
	fuzzBasesOnce sync.Once
	fuzzBases     []*Case
)

// bases: every real proof available plus a few synthetic shapes.
func bases(t testing.TB) []*Case {
	fuzzBasesOnce.Do(func() {
		for _, p := range allRealProofs(t) {
			fuzzBases = append(fuzzBases, p.Case())
		}
		r := rand.New(rand.NewSource(99))
		for _, cfg := range []synthConfig{
			{1, "equal", 0.5, 256, 256, 1, 1},
			{5, "skewed", 0.3, 256, 256, 2, 1},
			{64, "uniform", 0.5, 64, 256, 2, 2},
			{300, "uniform", 0.3, 256, 16, 3, 3},
		} {
			if c, _ := makeSynthetic(t, cfg, r); c != nil {
				fuzzBases = append(fuzzBases, c)
			}
		}
	})
	return fuzzBases
}

// Arbitrary proof bytes under a real verifier context.
func FuzzStateProofBytes(f *testing.F) {
	for i, b := range bases(f) {
		f.Add(uint8(i), b.Proof)
	}
	f.Fuzz(func(t *testing.T, ctx uint8, proof []byte) {
		bs := bases(t)
		c := *bs[int(ctx)%len(bs)]
		c.Proof = proof
		CompareCase(t, "fuzz/bytes", "fuzz", &c)
	})
}

// Chains of 1-6 structured mutations (fields, reveals, paths, context), driven by the fuzzer.
func FuzzStateProofStructured(f *testing.F) {
	for i := range bases(f) {
		f.Add(uint8(i), int64(i), uint8(1))
		f.Add(uint8(i), int64(i*7919), uint8(4))
	}
	sp := allSPMutations()
	cm := allCaseMutations()
	f.Fuzz(func(t *testing.T, ctx uint8, seed int64, steps uint8) {
		bs := bases(t)
		base := bs[int(ctx)%len(bs)]
		r := rand.New(rand.NewSource(seed))
		var m stateproof.StateProof
		if err := protocol.Decode(base.Proof, &m); err != nil {
			t.Fatal(err)
		}
		c := *base
		for s := 0; s < 1+int(steps)%6; s++ {
			if r.Intn(5) == 0 {
				cm[r.Intn(len(cm))].apply(&c, r)
			} else {
				sp[r.Intn(len(sp))].apply(&m, r)
				commitPending(&m)
			}
		}
		c.Proof = protocol.Encode(&m)
		CompareCase(t, "fuzz/structured", "fuzz", &c)
	})
}

// Message decoding and hashing, as the light node parses messages from blocks.
func FuzzMessage(f *testing.F) {
	for _, p := range allRealProofs(f) {
		f.Add(protocol.Encode(&p.Message))
	}
	f.Add([]byte{0x80})
	f.Fuzz(func(t *testing.T, raw []byte) {
		compareMessage(t, "fuzz/message", raw)
	})
}

// compareMessage decodes and hashes raw on both sides, with CompareCase's classification and
// failure policy: NON-CANONICAL differences fail only with DIFFTEST_STRICT=1.
func compareMessage(t testing.TB, group string, raw []byte) {
	t.Helper()
	var m stateproofmsg.Message
	gerr := protocol.Decode(raw, &m)
	canonical := gerr == nil && string(protocol.Encode(&m)) == string(raw)
	rh, rok, rerr := RustMsgDecodeHash(raw)
	g, r := Verdict{Status: Rejected}, Verdict{Status: Rejected}
	if gerr != nil {
		g.Err = gerr.Error()
	} else {
		g.Status = Accepted
	}
	if rok {
		r.Status = Accepted
	} else {
		r.Err = rerr
	}
	class := classify(g, r, canonical)
	detail := fmt.Sprintf("go=%d (%s) rust=%d (%s)", g.Status, g.Err, r.Status, r.Err)
	if class == "" && rok && rh != [32]byte(m.Hash()) {
		class, detail = ClassSoundness, "both decode, hashes differ"
	}
	stats.record(group, g, r, class)
	if class == "" {
		return
	}
	msg := fmt.Sprintf("%s divergence [%s]: %s raw=%x", class, group, detail, raw)
	if class == ClassNonCanonical && !failOnNonCanonical {
		t.Log(msg)
	} else {
		t.Error(msg)
	}
}

var (
	fuzzKeysOnce sync.Once
	fuzzKeys     []crypto.FalconSigner
)

// Falcon verification on arbitrary signatures and messages under fixed keys.
func FuzzFalcon(f *testing.F) {
	fuzzKeysOnce.Do(func() {
		for i := 0; i < 4; i++ {
			var seed crypto.FalconSeed
			seed[0] = byte(i)
			k, err := crypto.GenerateFalconSigner(seed)
			if err != nil {
				f.Fatal(err)
			}
			fuzzKeys = append(fuzzKeys, k)
		}
	})
	for i, k := range fuzzKeys {
		msg := []byte("fuzz message")
		sig, _ := k.SignBytes(msg)
		f.Add(uint8(i), []byte(sig), msg)
	}
	f.Fuzz(func(t *testing.T, key uint8, sig, msg []byte) {
		k := fuzzKeys[int(key)%len(fuzzKeys)]
		g := k.GetVerifyingKey().VerifyBytes(msg, crypto.FalconSignature(sig)) == nil
		r := RustFalconVerify(k.PublicKey[:], sig, msg)
		CompareValue(t, "fuzz/falcon", "fuzz", g == r, func() string {
			return "go and rust disagree on a Falcon signature"
		})
	})
}

// The weight inequality on arbitrary inputs.
func FuzzWeights(f *testing.F) {
	f.Add(uint64(1<<40), uint64(2230444), uint64(100), uint64(256))
	f.Fuzz(func(t *testing.T, s, l, n, st uint64) {
		g := stateproof.DiffVerifyWeights(s, l, n, st) == nil
		r := RustVerifyWeights(s, l, n, st)
		CompareValue(t, "fuzz/weights", "fuzz", g == r, func() string { return "verifyWeights disagree" })
	})
}

// recordingTB captures failures instead of failing the enclosing test.
type recordingTB struct {
	testing.TB
	failed bool
}

func (r *recordingTB) Helper()               {}
func (r *recordingTB) Log(...any)            {}
func (r *recordingTB) Error(...any)          { r.failed = true }
func (r *recordingTB) Errorf(string, ...any) { r.failed = true }

// compareMessage fails on a NON-CANONICAL difference only in strict mode, and always on
// canonical messages Rust rejects.
func TestMessageStrictPolicy(t *testing.T) {
	saved, savedStrict := stats, failOnNonCanonical
	t.Cleanup(func() { stats, failOnNonCanonical = saved, savedStrict })
	stats = &Stats{Compared: map[string]int{}, BothAccept: map[string]int{}, BothReject: map[string]int{}, Divergences: map[string]map[string]int{}}

	// An empty message map followed by a trailing nil: go-algorand decodes it, Rust rejects it.
	nonCanonical := []byte{0x80, 0xc0}
	for _, strict := range []bool{false, true} {
		failOnNonCanonical = strict
		rec := &recordingTB{TB: t}
		compareMessage(rec, "policy", nonCanonical)
		if rec.failed != strict {
			t.Errorf("strict=%v: failed=%v on a non-canonical difference", strict, rec.failed)
		}
	}
	if n := stats.Divergences[ClassNonCanonical]["policy"]; n != 2 {
		t.Errorf("recorded %d NON-CANONICAL divergences, want 2", n)
	}
	// Canonical messages still compare cleanly in both modes.
	for _, strict := range []bool{false, true} {
		failOnNonCanonical = strict
		for _, p := range allRealProofs(t) {
			rec := &recordingTB{TB: t}
			compareMessage(rec, "policy", protocol.Encode(&p.Message))
			if rec.failed {
				t.Errorf("strict=%v: canonical message reported as a divergence", strict)
			}
		}
	}
}
