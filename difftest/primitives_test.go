package difftest

// Component-level comparisons, where inputs are cheap enough to test in bulk and at the edges:
// the weight inequality, the Fiat-Shamir coins, Sumhash512, deterministic Falcon-1024, the
// message and light-header hashes, the transaction leaf, and the ln / proven-weight helpers
// used to derive anchors.

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	cfalcon "github.com/algorand/falcon"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/protocol"
)

func edgeUint64s() []uint64 {
	v := []uint64{0, 1, 2, 3, 4, 5, 7, 8, 255, 256, 257, 640, 641, 65535, 65536, 65537,
		math.MaxUint32 - 1, math.MaxUint32, math.MaxUint32 + 1, math.MaxUint64 - 1, math.MaxUint64,
		math.MaxInt64, math.MaxInt64 + 1}
	for k := uint(1); k < 64; k++ {
		v = append(v, 1<<k-1, 1<<k, 1<<k+1)
	}
	return v
}

// verifyWeights: an edge grid plus random inputs around the accept/reject boundary.
func TestWeights(t *testing.T) {
	signed := edgeUint64s()
	lnPW := []uint64{0, 1, 2, 45427, 45428, 65536, 1 << 20, 2230444, 2240612, 2317374, 1 << 40, math.MaxUint64}
	reveals := []uint64{0, 1, 2, 3, 10, 50, 100, 200, 400, 639, 640, 641, 1000, math.MaxUint64}
	strengths := []uint64{0, 1, 2, 16, 128, 256, 257, 512, math.MaxUint32, math.MaxUint64}
	check := func(s, l, n, st uint64) {
		g := stateproof.DiffVerifyWeights(s, l, n, st) == nil
		r := RustVerifyWeights(s, l, n, st)
		CompareValue(t, "weights", fmt.Sprintf("s%d-l%d-n%d-t%d", s, l, n, st), g == r, func() string {
			return fmt.Sprintf("go accepts=%v rust accepts=%v", g, r)
		})
	}
	for _, s := range signed {
		for _, l := range lnPW {
			for _, n := range reveals {
				for _, st := range strengths {
					check(s, l, n, st)
				}
			}
		}
	}
	// Random inputs near the boundary: for random (signed, lnPW, strength), every reveal count
	// in a window around the smallest accepted one.
	r := rand.New(rand.NewSource(7))
	for i := 0; i < envInt("DIFFTEST_WEIGHT_SAMPLES", 20000); i++ {
		s := r.Uint64() >> uint(r.Intn(64))
		l := uint64(r.Int63n(1 << 24))
		st := uint64(1 + r.Intn(600))
		lo, hi := uint64(0), uint64(641)
		for lo < hi { // smallest n Go accepts (monotone in n up to MaxReveals)
			mid := (lo + hi) / 2
			if stateproof.DiffVerifyWeights(s, l, mid, st) == nil {
				hi = mid
			} else {
				lo = mid + 1
			}
		}
		for n := lo; n+3 >= lo && n <= lo+3 && n <= 641; n++ {
			check(s, l, n, st)
		}
		if lo > 3 {
			for n := lo - 3; n < lo; n++ {
				check(s, l, n, st)
			}
		}
	}
}

// The coin sequence, including rejection sampling edges (tiny and huge signed weights).
func TestCoins(t *testing.T) {
	r := rand.New(rand.NewSource(8))
	weights := []uint64{1, 2, 3, 5, 1 << 32, 1<<63 - 1, 1 << 63, 1<<63 + 1, math.MaxUint64, math.MaxUint64 - 1, 6148914691236517206}
	for i := 0; i < envInt("DIFFTEST_COIN_SAMPLES", 3000); i++ {
		var w uint64
		if i < len(weights) {
			w = weights[i]
		} else {
			w = 1 + r.Uint64()>>uint(r.Intn(64))
		}
		voters := make([]byte, []int{64, 64, 64, 0, 32, 65}[r.Intn(6)])
		sigc := make([]byte, []int{64, 64, 64, 0, 63}[r.Intn(5)])
		r.Read(voters)
		r.Read(sigc)
		var h [32]byte
		r.Read(h[:])
		l := r.Uint64() >> uint(r.Intn(64))
		n := 1 + r.Intn(700)
		g := stateproof.DiffCoins(voters, l, sigc, w, h, n)
		rs := RustCoins(voters, l, sigc, w, h, n)
		CompareValue(t, "coins", fmt.Sprintf("w%d-n%d-%d", w, n, i), fmt.Sprint(g) == fmt.Sprint(rs), func() string {
			return fmt.Sprintf("first go %v rust %v", g[:min(4, n)], rs[:min(4, n)])
		})
	}
}

func TestSumhash512(t *testing.T) {
	r := rand.New(rand.NewSource(9))
	for i := 0; i < envInt("DIFFTEST_SUMHASH_SAMPLES", 5000); i++ {
		n := i
		if i > 600 {
			n = r.Intn(5000)
		}
		data := make([]byte, n)
		r.Read(data)
		h := crypto.HashFactory{HashType: crypto.Sumhash}.NewHash()
		h.Write(data)
		g := h.Sum(nil)
		rs := RustSumhash512(data)
		CompareValue(t, "sumhash512", fmt.Sprintf("len%d-%d", n, i), bytes.Equal(g, rs[:]), func() string {
			return fmt.Sprintf("go %x rust %x", g[:8], rs[:8])
		})
	}
}

// Deterministic Falcon-1024: valid signatures, and systematically damaged ones.
func TestFalcon(t *testing.T) {
	r := rand.New(rand.NewSource(10))
	keys := envInt("DIFFTEST_FALCON_KEYS", 12)
	for k := 0; k < keys; k++ {
		var seed crypto.FalconSeed
		r.Read(seed[:])
		signer, err := crypto.GenerateFalconSigner(seed)
		if err != nil {
			t.Fatal(err)
		}
		pk := signer.PublicKey[:]
		verifier := signer.GetVerifyingKey()
		for m := 0; m < 20; m++ {
			msg := make([]byte, []int{0, 1, 32, 32, 100, 1000}[r.Intn(6)])
			r.Read(msg)
			sig, err := signer.SignBytes(msg)
			if err != nil {
				t.Fatal(err)
			}
			variants := map[string][2][]byte{"valid": {sig, msg}}
			for f := 0; f < 20; f++ {
				s := cloneBytes(sig)
				flipBit(s, r)
				variants[fmt.Sprintf("sigflip%d", f)] = [2][]byte{s, msg}
			}
			for _, cut := range []int{1, 2, 10, len(sig) / 2, len(sig) - 2} {
				if cut < len(sig) {
					variants[fmt.Sprintf("sigcut%d", cut)] = [2][]byte{cloneBytes(sig[:len(sig)-cut]), msg}
				}
			}
			for _, extra := range [][]byte{{0}, {0xff}, {0, 0, 0}} {
				variants[fmt.Sprintf("sigext%x", extra)] = [2][]byte{append(cloneBytes(sig), extra...), msg}
			}
			for _, hdr := range []byte{0x00, 0x3a, 0x5a, 0xda, 0xff, sig[0] ^ 1} {
				s := cloneBytes(sig)
				s[0] = hdr
				variants[fmt.Sprintf("hdr%02x", hdr)] = [2][]byte{s, msg}
			}
			for _, salt := range []byte{0, 1, 2, 0xff} {
				s := cloneBytes(sig)
				s[1] = salt
				variants[fmt.Sprintf("salt%02x", salt)] = [2][]byte{s, msg}
			}
			if len(msg) > 0 {
				mm := cloneBytes(msg)
				flipBit(mm, r)
				variants["msgflip"] = [2][]byte{sig, mm}
			}
			variants["msgext"] = [2][]byte{sig, append(cloneBytes(msg), 0)}
			variants["empty"] = [2][]byte{nil, msg}
			rnd := make([]byte, len(sig))
			r.Read(rnd)
			rnd[0] = sig[0]
			variants["random-body"] = [2][]byte{rnd, msg}

			for name, v := range variants {
				g := verifier.VerifyBytes(v[1], crypto.FalconSignature(v[0])) == nil
				rs := RustFalconVerify(pk, v[0], v[1])
				CompareValue(t, "falcon/verify", fmt.Sprintf("k%d-m%d-%s", k, m, name), g == rs, func() string {
					return fmt.Sprintf("go accepts=%v rust accepts=%v", g, rs)
				})
				// ConvertToCT is only reached with a non-empty signature (buildCommittableSignature
				// rejects empty ones first; the C function would read out of bounds).
				if len(v[0]) == 0 {
					continue
				}
				cs := cfalcon.CompressedSignature(v[0])
				gct, gerr := cs.ConvertToCT()
				rct, rok := RustFalconToCT(v[0])
				same := (gerr == nil) == rok && (!rok || bytes.Equal(gct[:], rct))
				if !same && !g && !rs && gerr == nil && !rok {
					// Known, masked difference: the C converter ignores trailing bytes after a
					// valid compressed signature, the Rust decoder rejects them. Falcon verification
					// of the same bytes fails on both sides (checked just above), so a state proof
					// containing such a signature is rejected by both.
					recordMasked(t, "falcon/to-ct-trailing-bytes", fmt.Sprintf("k%d-m%d-%s", k, m, name))
					continue
				}
				CompareValue(t, "falcon/to-ct", fmt.Sprintf("k%d-m%d-%s", k, m, name), same, func() string {
					return fmt.Sprintf("go err=%v rust ok=%v", gerr, rok)
				})
			}
		}
		// Damaged public keys.
		msg := []byte("state proof message hash........")
		sig, _ := signer.SignBytes(msg)
		for f := 0; f < 30; f++ {
			bad := cloneBytes(pk)
			if f == 0 {
				bad[0] ^= 0xff
			} else {
				flipBit(bad, r)
			}
			var badPK cfalcon.PublicKey
			copy(badPK[:], bad)
			g := (&crypto.FalconVerifier{PublicKey: crypto.FalconPublicKey(badPK)}).VerifyBytes(msg, sig) == nil
			rs := RustFalconVerify(bad, sig, msg)
			CompareValue(t, "falcon/pk", fmt.Sprintf("k%d-pk%d", k, f), g == rs, func() string {
				return fmt.Sprintf("go accepts=%v rust accepts=%v", g, rs)
			})
		}
	}
}

// LnFormula is stateproof.LnIntApproximation's formula as cmd/lnref evaluates it.
func lnFormula(x uint64) uint64 {
	precision := uint64(1 << 16)
	return uint64(math.Ceil(math.Log(float64(x)) * float64(precision)))
}

// lnInputs: edge values plus, for every k, the integers nearest e^(k/2^16), where
// ceil(ln(x)*2^16) is most sensitive to the last bit of ln(x).
func lnInputs() []uint64 {
	xs := append([]uint64(nil), edgeUint64s()[1:]...)
	step := uint64(envInt("DIFFTEST_LN_STRIDE", 1))
	maxK := uint64(math.Log(math.MaxUint64) * 65536)
	for k := uint64(0); k <= maxK; k += step {
		f := math.Exp(float64(k) / 65536)
		if f >= math.MaxUint64 {
			break
		}
		xs = append(xs, nearby(uint64(math.Round(f)))...)
	}
	return xs
}

// nearby returns base-3..base+3 in unsigned arithmetic, leaving out 0 and values that would
// wrap below 0 or above MaxUint64.
func nearby(base uint64) []uint64 {
	var out []uint64
	for d := uint64(3); d >= 1; d-- {
		if base > d {
			out = append(out, base-d)
		}
	}
	if base != 0 {
		out = append(out, base)
	}
	for d := uint64(1); d <= 3; d++ {
		if base <= math.MaxUint64-d {
			out = append(out, base+d)
		}
	}
	return out
}

// goAmd64Ln evaluates the formula as go-algorand on amd64 does (natively, or through an amd64
// build of cmd/lnref under Rosetta). ok is false if amd64 binaries cannot run here.
func goAmd64Ln(t *testing.T, xs []uint64) ([]uint64, bool) {
	if runtime.GOARCH == "amd64" {
		out := make([]uint64, len(xs))
		for i, x := range xs {
			out[i] = lnFormula(x)
		}
		return out, true
	}
	bin := filepath.Join(t.TempDir(), "lnref-amd64")
	build := exec.Command("go", "build", "-o", bin, "./cmd/lnref")
	build.Env = append(os.Environ(), "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building amd64 lnref: %v\n%s", err, out)
	}
	var in bytes.Buffer
	for _, x := range xs {
		fmt.Fprintln(&in, x)
	}
	cmd := exec.Command(bin)
	cmd.Stdin = &in
	raw, err := cmd.Output()
	if err != nil {
		t.Logf("cannot run amd64 binaries here (%v)", err)
		return nil, false
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != len(xs) {
		t.Fatalf("lnref returned %d values for %d inputs", len(lines), len(xs))
	}
	out := make([]uint64, len(xs))
	for i, l := range lines {
		v, err := strconv.ParseUint(l, 10, 64)
		if err != nil {
			t.Fatalf("lnref: %q", l)
		}
		out[i] = v
	}
	return out, true
}

// The ln inputs reach the whole uint64 domain without wrapping at either end.
func TestLnInputs(t *testing.T) {
	for _, c := range []struct {
		base uint64
		want []uint64
	}{
		{0, []uint64{1, 2, 3}},
		{1, []uint64{1, 2, 3, 4}},
		{3, []uint64{1, 2, 3, 4, 5, 6}},
		{1 << 63, []uint64{1<<63 - 3, 1<<63 - 2, 1<<63 - 1, 1 << 63, 1<<63 + 1, 1<<63 + 2, 1<<63 + 3}},
		{math.MaxUint64 - 1, []uint64{math.MaxUint64 - 4, math.MaxUint64 - 3, math.MaxUint64 - 2, math.MaxUint64 - 1, math.MaxUint64}},
		{math.MaxUint64, []uint64{math.MaxUint64 - 3, math.MaxUint64 - 2, math.MaxUint64 - 1, math.MaxUint64}},
	} {
		if got := nearby(c.base); !slices.Equal(got, c.want) {
			t.Errorf("nearby(%d) = %v, want %v", c.base, got, c.want)
		}
	}
	// Every k with e^(k/2^16) in [2^63, 2^64) contributes candidates above 2^63.
	step := uint64(envInt("DIFFTEST_LN_STRIDE", 1))
	edges := map[uint64]bool{}
	for _, x := range edgeUint64s() {
		edges[x] = true
	}
	upper := 0
	for _, x := range lnInputs() {
		if x > 1<<63 && !edges[x] {
			upper++
		}
	}
	if want := int(math.Ln2 * 65536 / float64(step)); upper < want {
		t.Errorf("%d exponential-boundary inputs above 2^63, want at least %d", upper, want)
	}
	t.Logf("%d exponential-boundary inputs above 2^63", upper)
}

// ln(x) approximations. The reference is go-algorand on amd64 (what MainNet's nodes run).
// go-algorand on other architectures is compared too and reported as an upstream difference.
func TestLnIntApproximation(t *testing.T) {
	xs := lnInputs()
	// cmd/lnref's formula is go-algorand's function (checked on this architecture).
	for _, x := range xs {
		g, err := stateproof.LnIntApproximation(x)
		if err != nil || g != lnFormula(x) {
			t.Fatalf("lnref formula differs from stateproof.LnIntApproximation at %d", x)
		}
	}
	amd64, ok := goAmd64Ln(t, xs)
	if !ok {
		t.Skip("no amd64 reference on this machine; run on amd64 (or an arm64 Mac with Rosetta)")
	}
	for i, x := range xs {
		rs, rok := RustLnIntApproximation(x)
		ref := amd64[i]
		CompareValue(t, "ln-int-approx", fmt.Sprintf("x%d", x), rok && rs == ref, func() string {
			return fmt.Sprintf("go(amd64) %d rust %d", ref, rs)
		})
		if runtime.GOARCH != "amd64" {
			native := lnFormula(x)
			if native != ref {
				recordUpstream(t, "go-algorand-ln-amd64-vs-"+runtime.GOARCH, fmt.Sprintf("x=%d amd64=%d %s=%d", x, ref, runtime.GOARCH, native))
			} else {
				stats.record("go-algorand-ln-amd64-vs-"+runtime.GOARCH, Verdict{}, Verdict{}, "")
			}
		}
	}
	// Proven weight from total online weight (Muldiv(total, threshold, 2^32)).
	r := rand.New(rand.NewSource(11))
	threshold := uint64(1<<32) * 30 / 100
	for i := 0; i < 100000; i++ {
		total := r.Uint64() >> uint(r.Intn(64))
		g, overflow := basics.Muldiv(total, threshold, 1<<32)
		rs := RustProvenWeight(total)
		CompareValue(t, "proven-weight", fmt.Sprintf("t%d", total), overflow || g == rs, func() string {
			return fmt.Sprintf("go %d rust %d", g, rs)
		})
	}
}

// Message hashes, from fields (light client) and from msgpack (block parsing).
func TestMessageHash(t *testing.T) {
	r := rand.New(rand.NewSource(12))
	for i := 0; i < 5000; i++ {
		m := stateproofmsg.Message{
			LnProvenWeight:     []uint64{0, 1, r.Uint64()}[r.Intn(3)],
			FirstAttestedRound: basics.Round([]uint64{0, 1, r.Uint64()}[r.Intn(3)]),
			LastAttestedRound:  basics.Round([]uint64{0, 256, r.Uint64()}[r.Intn(3)]),
		}
		if r.Intn(8) > 0 {
			m.BlockHeadersCommitment = make([]byte, []int{32, 32, 0, 31, 33}[r.Intn(5)])
			r.Read(m.BlockHeadersCommitment)
		}
		if r.Intn(8) > 0 {
			m.VotersCommitment = make([]byte, []int{64, 64, 0, 63, 65}[r.Intn(5)])
			r.Read(m.VotersCommitment)
		}
		g := m.Hash()
		rs := RustMsgHash(m.BlockHeadersCommitment, m.VotersCommitment, m.LnProvenWeight, uint64(m.FirstAttestedRound), uint64(m.LastAttestedRound))
		CompareValue(t, "msg-hash/fields", fmt.Sprint(i), g == stateproof.MessageHash(rs), func() string {
			return fmt.Sprintf("go %x rust %x", g, rs)
		})
		enc := protocol.Encode(&m)
		rd, ok, err := RustMsgDecodeHash(enc)
		CompareValue(t, "msg-hash/decode", fmt.Sprint(i), ok && rd == [32]byte(g), func() string {
			return fmt.Sprintf("go %x rust %x ok=%v %s", g, rd, ok, err)
		})
	}
}

// Light block header leaves (the block headers commitment) and SHA-256 transaction leaves.
func TestLightHeaderAndTxnLeaf(t *testing.T) {
	r := rand.New(rand.NewSource(13))
	rnd32 := func(zeroP int) (b [32]byte) {
		if r.Intn(zeroP) != 0 {
			r.Read(b[:])
		}
		return
	}
	for i := 0; i < 20000; i++ {
		seed, bh, gh, tc := rnd32(3), rnd32(3), rnd32(8), rnd32(6)
		round := []uint64{0, 1, r.Uint64(), uint64(r.Intn(1 << 30))}[r.Intn(4)]
		lbh := bookkeeping.LightBlockHeader{
			Seed:                committee.Seed(seed),
			BlockHash:           bookkeeping.BlockHash(bh),
			Round:               basics.Round(round),
			GenesisHash:         crypto.Digest(gh),
			Sha256TxnCommitment: append([]byte(nil), tc[:]...), // as ToLightBlockHeader sets it
		}
		g := crypto.GenericHashObj(crypto.HashFactory{HashType: crypto.Sha256}.NewHash(), &lbh)
		rs := RustLightHeaderLeaf(seed, bh, round, gh, tc)
		CompareValue(t, "light-header-leaf", fmt.Sprint(i), bytes.Equal(g, rs[:]), func() string {
			return fmt.Sprintf("go %x rust %x (tc zero=%v)", g, rs, tc == [32]byte{})
		})
	}
	// Transaction leaf: SHA256("TL" || SHA256("TX"||txn) || SHA256("STIB"||stib)).
	for i := 0; i < 5000; i++ {
		txn := make([]byte, r.Intn(2000))
		stib := make([]byte, r.Intn(3000))
		r.Read(txn)
		r.Read(stib)
		id := sha256.Sum256(append([]byte(protocol.Transaction), txn...))
		sh := sha256.Sum256(append([]byte(protocol.SignedTxnInBlock), stib...))
		g := sha256.Sum256(append(append([]byte(protocol.TxnMerkleLeaf), id[:]...), sh[:]...))
		rs := RustTxnLeaf(txn, stib)
		CompareValue(t, "txn-leaf", fmt.Sprint(i), g == rs, func() string {
			return fmt.Sprintf("go %x rust %x", g, rs)
		})
	}
}
