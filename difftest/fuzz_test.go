package difftest

// Coverage-guided fuzzing (go test -fuzz). Seeds are real and synthetic proofs; the fuzzer
// explores from there. Any divergence fails and is saved under findings/ and testdata/fuzz/.
//
//	./run.sh -run '^$' -fuzz FuzzStateProofBytes -fuzztime 30m

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/protocol"
)

var (
	fuzzBasesOnce sync.Once
	fuzzBases     []*Case
	stableBases   int
)

// bases: a few synthetic shapes and the repo fixture, which are identical in every process and
// on every machine, then the optional corpus. Fuzz inputs name a context by index (see
// pickBase): indices below stableBases always mean the same context; the others map onto the
// corpus, so they depend on which corpus is present (a divergence's findings/ file holds its
// complete case either way).
func bases(t testing.TB) []*Case {
	fuzzBasesOnce.Do(func() {
		r := rand.New(rand.NewSource(99))
		for _, cfg := range []synthConfig{
			{1, "equal", 0.5, 256, 256, 1, 1},
			{5, "skewed", 0.3, 256, 256, 2, 1},
			{64, "uniform", 0.5, 64, 256, 2, 2},
			{300, "uniform", 0.3, 256, 16, 3, 3},
		} {
			c, why := makeSynthetic(t, cfg, r)
			if c == nil {
				t.Fatalf("fuzz base %s: %s", cfg, why)
			}
			fuzzBases = append(fuzzBases, c)
		}
		for _, p := range fixtureProofs(t) {
			fuzzBases = append(fuzzBases, p.Case())
		}
		stableBases = len(fuzzBases)
		for _, p := range corpusProofs(t) {
			fuzzBases = append(fuzzBases, p.Case())
		}
	})
	return fuzzBases
}

// pickBase maps a fuzz input's context index to a base (a copy).
func pickBase(t testing.TB, ctx uint8) Case {
	bs := bases(t)
	i := int(ctx)
	switch {
	case i < stableBases:
	case len(bs) == stableBases:
		i %= stableBases
	default:
		i = stableBases + (i-stableBases)%(len(bs)-stableBases)
	}
	return *bs[i]
}

// Arbitrary proof bytes under a real verifier context.
func FuzzStateProofBytes(f *testing.F) {
	for i, b := range bases(f) {
		if i <= math.MaxUint8 {
			f.Add(uint8(i), b.Proof)
		}
	}
	f.Fuzz(func(t *testing.T, ctx uint8, proof []byte) {
		c := pickBase(t, ctx)
		c.Proof = proof
		CompareCase(t, "fuzz/bytes", "fuzz", &c)
	})
}

// Chains of 1-6 structured mutations (fields, reveals, paths, context), driven by the fuzzer.
func FuzzStateProofStructured(f *testing.F) {
	for i := range bases(f) {
		if i <= math.MaxUint8 {
			f.Add(uint8(i), int64(i), uint8(1))
			f.Add(uint8(i), int64(i*7919), uint8(4))
		}
	}
	f.Fuzz(func(t *testing.T, ctx uint8, seed int64, steps uint8) {
		c := structuredCase(t, ctx, seed, steps)
		CompareCase(t, "fuzz/structured", "fuzz", c)
	})
}

var (
	spMutationsOnce sync.Once
	spMutations     []spMutation
	caseMutations   []caseMutation
)

// structuredCase applies the chain of mutations that (ctx, seed, steps) names.
func structuredCase(t testing.TB, ctx uint8, seed int64, steps uint8) *Case {
	spMutationsOnce.Do(func() {
		spMutations, caseMutations = allSPMutations(), allCaseMutations()
	})
	c := pickBase(t, ctx)
	r := rand.New(rand.NewSource(seed))
	var m stateproof.StateProof
	if err := protocol.Decode(c.Proof, &m); err != nil {
		t.Fatal(err)
	}
	for s := 0; s < 1+int(steps)%6; s++ {
		if r.Intn(5) == 0 {
			caseMutations[r.Intn(len(caseMutations))].apply(&c, r)
		} else {
			spMutations[r.Intn(len(spMutations))].apply(&m, r)
			commitPending(&m)
		}
	}
	c.Proof = protocol.Encode(&m)
	return &c
}

// Message decoding and hashing, as the light node parses messages from blocks.
func FuzzMessage(f *testing.F) {
	for _, p := range allRealProofs(f) {
		f.Add(protocol.Encode(&p.Message))
	}
	f.Add([]byte{0x80})
	f.Fuzz(func(t *testing.T, raw []byte) {
		var m stateproofmsg.Message
		gerr := protocol.Decode(raw, &m)
		canonical := gerr == nil && string(protocol.Encode(&m)) == string(raw)
		rh, rok, rerr := RustMsgDecodeHash(raw)
		switch {
		case rok && gerr != nil:
			t.Errorf("SOUNDNESS divergence [fuzz/message]: rust decodes what go rejects (%v) raw=%x", gerr, raw)
		case rok && rh != [32]byte(m.Hash()):
			t.Errorf("SOUNDNESS divergence [fuzz/message]: hashes differ raw=%x", raw)
		case !rok && canonical:
			t.Errorf("LIVENESS divergence [fuzz/message]: rust rejects canonical message (%s) raw=%x", rerr, raw)
		}
		g, r := Verdict{Status: Rejected}, Verdict{Status: Rejected}
		if gerr == nil {
			g.Status = Accepted
		}
		if rok {
			r.Status = Accepted
		}
		stats.record("fuzz/message", g, r, classify(g, r, canonical))
	})
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

// fuzzBasesDigest hashes the stable fuzz contexts and a structured fuzz input built on each.
func fuzzBasesDigest(t testing.TB) [32]byte {
	h := sha256.New()
	put := func(c *Case) {
		for _, b := range [][]byte{c.Voters, c.MsgHash[:], c.Proof} {
			binary.Write(h, binary.BigEndian, uint64(len(b)))
			h.Write(b)
		}
		binary.Write(h, binary.BigEndian, []uint64{c.LnPW, c.Strength, c.Round})
	}
	bs := bases(t)
	for i := 0; i < stableBases; i++ {
		put(bs[i])
		put(structuredCase(t, uint8(i), int64(7919*i+3), 4))
	}
	return [32]byte(h.Sum(nil))
}

// The stable fuzz contexts, and structured fuzz inputs built on them, are the same in a fresh
// process: the synthetic seeds the parent adds stay valid in its fuzz workers, and a saved fuzz
// input always names the same proof and trusted inputs.
func TestFuzzBasesDeterministic(t *testing.T) {
	digest := fuzzBasesDigest(t)
	if os.Getenv("DIFFTEST_DIGEST_CHILD") == "1" {
		fmt.Printf("DIGEST %x\n", digest)
		return
	}
	for i, c := range bases(t)[:stableBases] {
		if g, _ := GoVerify(c); g.Status != Accepted {
			t.Errorf("base %d: go-algorand rejects: %s", i, g.Err)
		}
		if r := RustVerifyCase(c); r.Status != Accepted {
			t.Errorf("base %d: rust rejects: %s", i, r.Err)
		}
	}

	// A fresh process (empty key cache) builds the same contexts and inputs.
	cmd := exec.Command(os.Args[0], "-test.run=^TestFuzzBasesDeterministic$", "-test.count=1")
	cmd.Env = append(os.Environ(), "DIFFTEST_DIGEST_CHILD=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("child process: %v\n%s", err, out)
	}
	want := fmt.Sprintf("DIGEST %x", digest)
	if !strings.Contains(string(out), want) {
		t.Errorf("fresh process built different fuzz contexts: want %s, got\n%s", want, out)
	}

	// The same configuration and RNG seed with an empty key cache give the same case, so one
	// case's proof verifies under the other's context.
	cfg := synthConfig{1, "equal", 0.5, 256, 256, 1, 1}
	c1, _ := makeSynthetic(t, cfg, rand.New(rand.NewSource(99)))
	saved := signerCache
	signerCache = map[[3]uint64]*merklesignature.Secrets{}
	t.Cleanup(func() { signerCache = saved })
	c2, _ := makeSynthetic(t, cfg, rand.New(rand.NewSource(99)))
	if c1 == nil || c2 == nil || !reflect.DeepEqual(c1, c2) {
		t.Fatalf("rebuilt synthetic case differs")
	}
	c := *c2
	c.Proof = c1.Proof
	if g, _ := GoVerify(&c); g.Status != Accepted {
		t.Errorf("go-algorand rejects the first proof under the rebuilt context: %s", g.Err)
	}
	if r := RustVerifyCase(&c); r.Status != Accepted {
		t.Errorf("rust rejects the first proof under the rebuilt context: %s", r.Err)
	}
}
