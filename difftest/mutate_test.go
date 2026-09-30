package difftest

// Structured mutations: decode a proof with go-algorand, change one field, re-encode it
// canonically, and compare both verifiers on the result. Each mutation targets one check of
// Verifier.Verify (weights, salt, Falcon, the MSS path, both vector commitments, coins, ...).

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
	"sync"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/protocol"
)

type spMutation struct {
	name  string
	apply func(sp *stateproof.StateProof, r *rand.Rand) bool // false: not applicable
}

type caseMutation struct {
	name  string
	apply func(c *Case, r *rand.Rand)
}

func flipBit(b []byte, r *rand.Rand) {
	if len(b) > 0 {
		i := r.Intn(len(b))
		b[i] ^= 1 << uint(r.Intn(8))
	}
}

func cloneBytes(b []byte) []byte { return append([]byte(nil), b...) }

// revealPositions returns the reveal map keys in order.
func revealPositions(sp *stateproof.StateProof) []uint64 {
	pos := make([]uint64, 0, len(sp.Reveals))
	for p := range sp.Reveals {
		pos = append(pos, p)
	}
	sort.Slice(pos, func(i, j int) bool { return pos[i] < pos[j] })
	return pos
}

func pickReveal(sp *stateproof.StateProof, r *rand.Rand) (uint64, bool) {
	pos := revealPositions(sp)
	if len(pos) == 0 {
		return 0, false
	}
	return pos[r.Intn(len(pos))], true
}

// withReveal mutates one randomly chosen reveal in place.
func withReveal(f func(rv *stateproof.Reveal, r *rand.Rand) bool) func(*stateproof.StateProof, *rand.Rand) bool {
	return func(sp *stateproof.StateProof, r *rand.Rand) bool {
		p, ok := pickReveal(sp, r)
		if !ok {
			return false
		}
		rv := sp.Reveals[p]
		if !f(&rv, r) {
			return false
		}
		sp.Reveals[p] = rv
		return true
	}
}

func mutatePath(path *[]crypto.GenericDigest, r *rand.Rand, kind int) bool {
	p := *path
	switch kind {
	case 0: // flip a bit in one element
		if len(p) == 0 {
			return false
		}
		i := r.Intn(len(p))
		p[i] = cloneBytes(p[i])
		flipBit(p[i], r)
	case 1: // drop an element
		if len(p) == 0 {
			return false
		}
		i := r.Intn(len(p))
		*path = append(p[:i:i], p[i+1:]...)
	case 2: // append a random element
		e := make([]byte, 64)
		r.Read(e)
		*path = append(p, e)
	case 3: // swap two elements
		if len(p) < 2 {
			return false
		}
		i, j := r.Intn(len(p)), r.Intn(len(p))
		if i == j || string(p[i]) == string(p[j]) {
			return false
		}
		p[i], p[j] = p[j], p[i]
	case 4: // truncate one element
		if len(p) == 0 {
			return false
		}
		i := r.Intn(len(p))
		if len(p[i]) == 0 {
			return false
		}
		p[i] = cloneBytes(p[i][:len(p[i])-1])
	case 5: // an empty element
		if len(p) == 0 {
			return false
		}
		p[r.Intn(len(p))] = crypto.GenericDigest{}
	}
	return true
}

var uint64Edges = []func(v uint64, r *rand.Rand) uint64{
	func(v uint64, _ *rand.Rand) uint64 { return v + 1 },
	func(v uint64, _ *rand.Rand) uint64 { return v - 1 },
	func(uint64, *rand.Rand) uint64 { return 0 },
	func(uint64, *rand.Rand) uint64 { return 1 },
	func(uint64, *rand.Rand) uint64 { return math.MaxUint64 },
	func(v uint64, _ *rand.Rand) uint64 { return v * 2 },
	func(v uint64, _ *rand.Rand) uint64 { return v / 2 },
	func(v uint64, _ *rand.Rand) uint64 { return v ^ (1 << 63) },
	func(v uint64, r *rand.Rand) uint64 { return r.Uint64() },
}

func edgeMutations(name string, get func(*stateproof.StateProof, *rand.Rand) *uint64) []spMutation {
	var out []spMutation
	for i, edge := range uint64Edges {
		edge := edge
		out = append(out, spMutation{fmt.Sprintf("%s-edge%d", name, i), func(sp *stateproof.StateProof, r *rand.Rand) bool {
			p := get(sp, r)
			if p == nil {
				return false
			}
			nv := edge(*p, r)
			if nv == *p {
				return false
			}
			*p = nv
			return true
		}})
	}
	return out
}

// revealField picks a random reveal and returns a pointer into a copy of it; commitPending
// stores the copy back into the map (reveals are map values, so they cannot be addressed).
func revealField(f func(rv *stateproof.Reveal) *uint64) func(*stateproof.StateProof, *rand.Rand) *uint64 {
	return func(sp *stateproof.StateProof, r *rand.Rand) *uint64 {
		p, ok := pickReveal(sp, r)
		if !ok {
			return nil
		}
		rv := sp.Reveals[p]
		pendingMu.Lock()
		pending[sp] = append(pending[sp], pendingWrite{p, &rv})
		pendingMu.Unlock()
		return f(&rv)
	}
}

type pendingWrite struct {
	pos uint64
	rv  *stateproof.Reveal
}

var (
	pendingMu sync.Mutex
	pending   = map[*stateproof.StateProof][]pendingWrite{}
)

func commitPending(sp *stateproof.StateProof) {
	pendingMu.Lock()
	defer pendingMu.Unlock()
	for _, w := range pending[sp] {
		sp.Reveals[w.pos] = *w.rv
	}
	delete(pending, sp)
}

type merkleProof = merklearray.Proof

type testTB = testing.TB

func allSPMutations() []spMutation {
	var m []spMutation
	m = append(m, edgeMutations("signedWeight", func(sp *stateproof.StateProof, _ *rand.Rand) *uint64 { return &sp.SignedWeight })...)
	m = append(m, edgeMutations("reveal-L", revealField(func(rv *stateproof.Reveal) *uint64 { return &rv.SigSlot.L }))...)
	m = append(m, edgeMutations("reveal-weight", revealField(func(rv *stateproof.Reveal) *uint64 { return &rv.Part.Weight }))...)
	m = append(m, edgeMutations("reveal-keyLifetime", revealField(func(rv *stateproof.Reveal) *uint64 { return &rv.Part.PK.KeyLifetime }))...)
	m = append(m, edgeMutations("reveal-vcIndex", revealField(func(rv *stateproof.Reveal) *uint64 { return &rv.SigSlot.Sig.VectorCommitmentIndex }))...)
	m = append(m, edgeMutations("positionToReveal", func(sp *stateproof.StateProof, r *rand.Rand) *uint64 {
		if len(sp.PositionsToReveal) == 0 {
			return nil
		}
		return &sp.PositionsToReveal[r.Intn(len(sp.PositionsToReveal))]
	})...)

	m = append(m,
		spMutation{"sigCommit-flip", func(sp *stateproof.StateProof, r *rand.Rand) bool {
			sp.SigCommit = cloneBytes(sp.SigCommit)
			flipBit(sp.SigCommit, r)
			return true
		}},
		spMutation{"sigCommit-short", func(sp *stateproof.StateProof, r *rand.Rand) bool {
			if len(sp.SigCommit) == 0 {
				return false
			}
			sp.SigCommit = cloneBytes(sp.SigCommit[:len(sp.SigCommit)-1])
			return true
		}},
		spMutation{"sigCommit-long", func(sp *stateproof.StateProof, r *rand.Rand) bool {
			sp.SigCommit = append(cloneBytes(sp.SigCommit), byte(r.Intn(256)))
			return true
		}},
		spMutation{"sigCommit-empty", func(sp *stateproof.StateProof, r *rand.Rand) bool {
			sp.SigCommit = nil
			return true
		}},
		spMutation{"saltVersion", func(sp *stateproof.StateProof, r *rand.Rand) bool {
			sp.MerkleSignatureSaltVersion += byte(1 + r.Intn(255))
			return true
		}},
		spMutation{"positions-swap", func(sp *stateproof.StateProof, r *rand.Rand) bool {
			p := sp.PositionsToReveal
			if len(p) < 2 {
				return false
			}
			i, j := r.Intn(len(p)), r.Intn(len(p))
			if p[i] == p[j] {
				return false
			}
			p[i], p[j] = p[j], p[i]
			return true
		}},
		spMutation{"positions-drop", func(sp *stateproof.StateProof, r *rand.Rand) bool {
			p := sp.PositionsToReveal
			if len(p) == 0 {
				return false
			}
			i := r.Intn(len(p))
			sp.PositionsToReveal = append(p[:i:i], p[i+1:]...)
			return true
		}},
		spMutation{"positions-dup", func(sp *stateproof.StateProof, r *rand.Rand) bool {
			p := sp.PositionsToReveal
			if len(p) == 0 {
				return false
			}
			sp.PositionsToReveal = append(p, p[r.Intn(len(p))])
			return true
		}},
		spMutation{"positions-other-reveal", func(sp *stateproof.StateProof, r *rand.Rand) bool {
			p := sp.PositionsToReveal
			pos := revealPositions(sp)
			if len(p) == 0 || len(pos) < 2 {
				return false
			}
			i := r.Intn(len(p))
			np := pos[r.Intn(len(pos))]
			if np == p[i] {
				return false
			}
			p[i] = np
			return true
		}},
		spMutation{"positions-640", func(sp *stateproof.StateProof, r *rand.Rand) bool {
			return padPositions(sp, 640)
		}},
		spMutation{"positions-641", func(sp *stateproof.StateProof, r *rand.Rand) bool {
			return padPositions(sp, 641)
		}},
		spMutation{"reveals-641", func(sp *stateproof.StateProof, r *rand.Rand) bool {
			p, ok := pickReveal(sp, r)
			if !ok {
				return false
			}
			for np := uint64(0); len(sp.Reveals) < 641; np++ {
				if _, taken := sp.Reveals[np]; !taken {
					sp.Reveals[np] = sp.Reveals[p]
				}
			}
			return true
		}},
		spMutation{"positions-empty", func(sp *stateproof.StateProof, r *rand.Rand) bool {
			sp.PositionsToReveal = nil
			return true
		}},
		spMutation{"reveal-delete", func(sp *stateproof.StateProof, r *rand.Rand) bool {
			p, ok := pickReveal(sp, r)
			if !ok {
				return false
			}
			delete(sp.Reveals, p)
			return true
		}},
		spMutation{"reveal-move", func(sp *stateproof.StateProof, r *rand.Rand) bool {
			p, ok := pickReveal(sp, r)
			if !ok {
				return false
			}
			np := p + 1 + uint64(r.Intn(3))
			if _, taken := sp.Reveals[np]; taken {
				return false
			}
			sp.Reveals[np] = sp.Reveals[p]
			delete(sp.Reveals, p)
			return true
		}},
		spMutation{"reveal-extra-copy", func(sp *stateproof.StateProof, r *rand.Rand) bool {
			p, ok := pickReveal(sp, r)
			if !ok {
				return false
			}
			np := p + 1
			if _, taken := sp.Reveals[np]; taken {
				return false
			}
			sp.Reveals[np] = sp.Reveals[p]
			return true
		}},
		spMutation{"reveals-all-deleted", func(sp *stateproof.StateProof, r *rand.Rand) bool {
			sp.Reveals = map[uint64]stateproof.Reveal{}
			return true
		}},
		spMutation{"reveal-falcon-flip", withReveal(func(rv *stateproof.Reveal, r *rand.Rand) bool {
			s := cloneBytes(rv.SigSlot.Sig.Signature)
			flipBit(s, r)
			rv.SigSlot.Sig.Signature = s
			return true
		})},
		spMutation{"reveal-falcon-truncate", withReveal(func(rv *stateproof.Reveal, r *rand.Rand) bool {
			s := rv.SigSlot.Sig.Signature
			if len(s) < 2 {
				return false
			}
			rv.SigSlot.Sig.Signature = cloneBytes(s[:len(s)-1-r.Intn(len(s)/2)])
			return true
		})},
		spMutation{"reveal-falcon-append", withReveal(func(rv *stateproof.Reveal, r *rand.Rand) bool {
			rv.SigSlot.Sig.Signature = append(cloneBytes(rv.SigSlot.Sig.Signature), byte(r.Intn(256)))
			return true
		})},
		spMutation{"reveal-falcon-empty", withReveal(func(rv *stateproof.Reveal, r *rand.Rand) bool {
			rv.SigSlot.Sig.Signature = nil
			return true
		})},
		spMutation{"reveal-falcon-header", withReveal(func(rv *stateproof.Reveal, r *rand.Rand) bool {
			s := cloneBytes(rv.SigSlot.Sig.Signature)
			if len(s) == 0 {
				return false
			}
			s[0] ^= byte(1 + r.Intn(255))
			rv.SigSlot.Sig.Signature = s
			return true
		})},
		spMutation{"reveal-falcon-salt", withReveal(func(rv *stateproof.Reveal, r *rand.Rand) bool {
			s := cloneBytes(rv.SigSlot.Sig.Signature)
			if len(s) < 2 {
				return false
			}
			s[1] ^= byte(1 + r.Intn(255))
			rv.SigSlot.Sig.Signature = s
			return true
		})},
		spMutation{"reveal-vkey-flip", withReveal(func(rv *stateproof.Reveal, r *rand.Rand) bool {
			k := rv.SigSlot.Sig.VerifyingKey.PublicKey
			i := r.Intn(len(k))
			k[i] ^= 1 << uint(r.Intn(8))
			rv.SigSlot.Sig.VerifyingKey.PublicKey = k
			return true
		})},
		spMutation{"reveal-vkey-header", withReveal(func(rv *stateproof.Reveal, r *rand.Rand) bool {
			rv.SigSlot.Sig.VerifyingKey.PublicKey[0] ^= byte(1 + r.Intn(255))
			return true
		})},
		spMutation{"reveal-pk-commitment-flip", withReveal(func(rv *stateproof.Reveal, r *rand.Rand) bool {
			c := rv.Part.PK.Commitment
			i := r.Intn(len(c))
			c[i] ^= 1 << uint(r.Intn(8))
			rv.Part.PK.Commitment = c
			return true
		})},
		spMutation{"reveal-sig-zeroed", withReveal(func(rv *stateproof.Reveal, r *rand.Rand) bool {
			rv.SigSlot.Sig = merklesignature.Signature{}
			return true
		})},
		spMutation{"reveal-mss-depth", withReveal(func(rv *stateproof.Reveal, r *rand.Rand) bool {
			d := &rv.SigSlot.Sig.Proof.TreeDepth
			*d = uint8(int(*d) + []int{-1, 1, 2, 17 - int(*d), 16 - int(*d), 21 - int(*d)}[r.Intn(6)])
			return true
		})},
		spMutation{"reveal-mss-hashtype", withReveal(func(rv *stateproof.Reveal, r *rand.Rand) bool {
			h := &rv.SigSlot.Sig.Proof.HashFactory.HashType
			*h = crypto.HashType((int(*h) + 1 + r.Intn(3)) % 4)
			return true
		})},
	)
	for kind := 0; kind < 6; kind++ {
		kind := kind
		m = append(m,
			spMutation{fmt.Sprintf("reveal-mss-path%d", kind), withReveal(func(rv *stateproof.Reveal, r *rand.Rand) bool {
				rv.SigSlot.Sig.Proof.Path = append([]crypto.GenericDigest(nil), rv.SigSlot.Sig.Proof.Path...)
				return mutatePath(&rv.SigSlot.Sig.Proof.Path, r, kind)
			})},
			spMutation{fmt.Sprintf("sigProofs-path%d", kind), func(sp *stateproof.StateProof, r *rand.Rand) bool {
				sp.SigProofs.Path = append([]crypto.GenericDigest(nil), sp.SigProofs.Path...)
				return mutatePath(&sp.SigProofs.Path, r, kind)
			}},
			spMutation{fmt.Sprintf("partProofs-path%d", kind), func(sp *stateproof.StateProof, r *rand.Rand) bool {
				sp.PartProofs.Path = append([]crypto.GenericDigest(nil), sp.PartProofs.Path...)
				return mutatePath(&sp.PartProofs.Path, r, kind)
			}},
		)
	}
	for _, which := range []string{"sigProofs", "partProofs"} {
		which := which
		proof := func(sp *stateproof.StateProof) *merkleProof {
			if which == "sigProofs" {
				return &sp.SigProofs
			}
			return &sp.PartProofs
		}
		m = append(m,
			spMutation{which + "-depth", func(sp *stateproof.StateProof, r *rand.Rand) bool {
				p := proof(sp)
				p.TreeDepth = uint8(int(p.TreeDepth) + []int{-1, 1, 2, -2, 20 - int(p.TreeDepth), 21 - int(p.TreeDepth), -int(p.TreeDepth)}[r.Intn(7)])
				return true
			}},
			spMutation{which + "-hashtype", func(sp *stateproof.StateProof, r *rand.Rand) bool {
				p := proof(sp)
				p.HashFactory.HashType = crypto.HashType((int(p.HashFactory.HashType) + 1 + r.Intn(3)) % 4)
				return true
			}},
			spMutation{which + "-path-empty", func(sp *stateproof.StateProof, r *rand.Rand) bool {
				p := proof(sp)
				if len(p.Path) == 0 {
					return false
				}
				p.Path = nil
				return true
			}},
		)
	}
	return m
}

// padPositions repeats existing positions until there are n (the decoders allow 640).
func padPositions(sp *stateproof.StateProof, n int) bool {
	p := sp.PositionsToReveal
	if len(p) == 0 || len(p) >= n {
		return false
	}
	for i := 0; len(sp.PositionsToReveal) < n; i++ {
		sp.PositionsToReveal = append(sp.PositionsToReveal, p[i%len(p)])
	}
	return true
}

func allCaseMutations() []caseMutation {
	return []caseMutation{
		{"voters-flip", func(c *Case, r *rand.Rand) { c.Voters = cloneBytes(c.Voters); flipBit(c.Voters, r) }},
		{"voters-short", func(c *Case, r *rand.Rand) {
			if len(c.Voters) > 0 {
				c.Voters = cloneBytes(c.Voters[:len(c.Voters)-1])
			}
		}},
		{"voters-empty", func(c *Case, r *rand.Rand) { c.Voters = nil }},
		{"lnPW+1", func(c *Case, r *rand.Rand) { c.LnPW++ }},
		{"lnPW-1", func(c *Case, r *rand.Rand) { c.LnPW-- }},
		{"lnPW-0", func(c *Case, r *rand.Rand) { c.LnPW = 0 }},
		{"lnPW-max", func(c *Case, r *rand.Rand) { c.LnPW = math.MaxUint64 }},
		{"lnPW-small", func(c *Case, r *rand.Rand) { c.LnPW = uint64(r.Intn(1 << 20)) }},
		{"round+1", func(c *Case, r *rand.Rand) { c.Round++ }},
		{"round-1", func(c *Case, r *rand.Rand) { c.Round-- }},
		{"round+256", func(c *Case, r *rand.Rand) { c.Round += 256 }},
		{"round-256", func(c *Case, r *rand.Rand) { c.Round -= 256 }},
		{"round-0", func(c *Case, r *rand.Rand) { c.Round = 0 }},
		{"msgHash-flip", func(c *Case, r *rand.Rand) { flipBit(c.MsgHash[:], r) }},
		{"strength+1", func(c *Case, r *rand.Rand) { c.Strength++ }},
		{"strength-1", func(c *Case, r *rand.Rand) { c.Strength-- }},
		{"strength-0", func(c *Case, r *rand.Rand) { c.Strength = 0 }},
		{"strength-max", func(c *Case, r *rand.Rand) { c.Strength = math.MaxUint64 }},
		{"strength-half", func(c *Case, r *rand.Rand) { c.Strength /= 2 }},
	}
}

// mutateAndCompare applies every mutation `draws` times to base and compares both verifiers.
func mutateAndCompare(t testTB, group, label string, base *Case, draws int, seed int64) {
	var sp stateproof.StateProof
	if err := protocol.Decode(base.Proof, &sp); err != nil {
		t.Fatalf("%s: base proof does not decode: %v", label, err)
	}
	r := rand.New(rand.NewSource(seed))
	for _, mut := range allSPMutations() {
		for d := 0; d < draws; d++ {
			var m stateproof.StateProof
			if err := protocol.Decode(base.Proof, &m); err != nil {
				t.Fatal(err)
			}
			applied := mut.apply(&m, r)
			commitPending(&m)
			if !applied {
				continue
			}
			c := *base
			c.Proof = protocol.Encode(&m)
			CompareCase(t, group+"/mut", fmt.Sprintf("%s-%s-%d", label, mut.name, d), &c)
		}
	}
	for _, mut := range allCaseMutations() {
		for d := 0; d < draws; d++ {
			c := *base
			mut.apply(&c, r)
			CompareCase(t, group+"/ctx", fmt.Sprintf("%s-%s-%d", label, mut.name, d), &c)
		}
	}
}
