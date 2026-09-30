package difftest

// Real blocks and SHA-256 vector commitment paths: the pieces between a verified block
// headers commitment and a transaction (what the light node's verify-tx checks).

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
)

// The round whose header first commits to voters (state proofs start after it).
var firstVotersRound = map[string]uint64{"mainnet": 23_591_680, "testnet": 24_098_560}

// Each real block: the light header leaf Rust derives from the raw bytes equals go-algorand's
// ToLightBlockHeader() leaf; for blocks carrying a state proof, Rust extracts the same message
// and proof go-algorand decodes.
func TestRealBlocks(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("corpus", "*-blocks", "*.bin"))
	if len(files) == 0 {
		t.Skip("no corpus/ (run ./fetch-corpus.sh)")
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var b rpcs.EncodedBlockCert
		if err := protocol.Decode(raw, &b); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		label := strings.TrimSuffix(filepath.Base(filepath.Dir(f)), "-blocks") + "-" + strings.TrimSuffix(filepath.Base(f), ".bin")

		lbh := b.Block.ToLightBlockHeader()
		g := crypto.GenericHashObj(crypto.HashFactory{HashType: crypto.Sha256}.NewHash(), &lbh)
		rs, ok, rerr := RustBlockLightHeaderLeaf(raw)
		era := "seed"
		if lbh.BlockHash != ([32]byte{}) {
			era = "blockhash"
		}
		same := ok && bytes.Equal(g, rs[:])
		net := strings.TrimSuffix(filepath.Base(filepath.Dir(f)), "-blocks")
		if !same && uint64(b.Block.Round()) < firstVotersRound[net] {
			// Known, out of domain: before state proofs were enabled (consensus < v34) no light
			// header is ever committed to. go-algorand's ToLightBlockHeader uses the seed for every
			// protocol without StateProofBlockHashInLightHeader; the Rust host code lists only the
			// seed-era state proof protocols (v34-v38) so that future protocols default to the
			// block hash. Every block from the first voters round on is compared strictly.
			recordMasked(t, "block/light-header-before-state-proofs", label)
		} else {
			CompareValue(t, "block/light-header-"+era, label, same, func() string {
				return fmt.Sprintf("go %x rust %x ok=%v %s", g, rs, ok, rerr)
			})
		}

		if strings.HasPrefix(filepath.Base(f), "h") {
			continue // header-only sample
		}
		txns, err := b.Block.DecodePaysetFlat()
		if err != nil {
			t.Fatal(err)
		}
		// The payset commitment go-algorand computes equals the header's (sanity for the leaf test).
		tree, err := b.Block.TxnMerkleTreeSHA256()
		if err != nil {
			t.Fatal(err)
		}
		root := tree.Root()
		if len(txns) > 0 && !bytes.Equal(root, b.Block.Sha256Commitment[:]) {
			t.Errorf("%s: go-algorand's own SHA-256 payset root differs from the header", label)
		}
		for _, tx := range txns {
			if tx.Txn.Type != protocol.StateProofTx {
				continue
			}
			first := uint64(tx.Txn.Message.FirstAttestedRound)
			gm := tx.Txn.Message.Hash()
			gp := sha256.Sum256(protocol.Encode(&tx.Txn.StateProof))
			rm, rp, st := RustBlockStpf(raw, first)
			CompareValue(t, "block/stpf-extract", fmt.Sprintf("%s-%d", label, first),
				st == 0 && rm == [32]byte(gm) && rp == gp, func() string {
					return fmt.Sprintf("status %d msg go %x rust %x proof go %x rust %x", st, gm, rm, gp, rp)
				})
		}
	}
}

var verbose = os.Getenv("DIFFTEST_VERBOSE") == "1"

type rawLeaf []byte

func (l rawLeaf) ToBeHashed() (protocol.HashID, []byte) { return "TL", l }

type leafArray []rawLeaf

func (a leafArray) Length() uint64                             { return uint64(len(a)) }
func (a leafArray) Marshal(pos uint64) (crypto.Hashable, error) { return a[pos], nil }

func leafHash(l rawLeaf) [32]byte { return sha256.Sum256(append([]byte("TL"), l...)) }

// SHA-256 vector commitments of every size up to 600 leaves (and power-of-two edges): for each
// leaf, go-algorand's single-leaf proof must recompute the root in Rust, and damaged proofs
// (wrong index, depth, sibling, leaf) must be accepted or rejected identically.
func TestSha256VectorCommitment(t *testing.T) {
	r := rand.New(rand.NewSource(14))
	sizes := []int{1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513}
	for len(sizes) < envInt("DIFFTEST_VC_TREES", 120) {
		sizes = append(sizes, 1+r.Intn(600))
	}
	for _, n := range sizes {
		leaves := make(leafArray, n)
		for i := range leaves {
			leaves[i] = make(rawLeaf, 1+r.Intn(40))
			r.Read(leaves[i])
		}
		tree, err := merklearray.BuildVectorCommitmentTree(leaves, crypto.HashFactory{HashType: crypto.Sha256})
		if err != nil {
			t.Fatal(err)
		}
		root := tree.Root()
		indices := r.Perm(n)
		if len(indices) > 40 {
			indices = indices[:40]
		}
		for _, idx := range indices {
			proof, err := tree.ProveSingleLeaf(uint64(idx))
			if err != nil {
				t.Fatal(err)
			}
			path := make([][32]byte, len(proof.Path))
			for i, p := range proof.Path {
				copy(path[i][:], p)
			}
			label := fmt.Sprintf("n%d-i%d", n, idx)
			rr, ok := RustSha256VCRoot(leafHash(leaves[idx]), uint64(idx), proof.TreeDepth, path)
			CompareValue(t, "vc/honest", label, ok && bytes.Equal(rr[:], root), func() string {
				return fmt.Sprintf("go root %x rust %x ok=%v", root, rr, ok)
			})

			// Damaged variants: the verdict is "recomputes the committed root".
			type variant struct {
				name  string
				idx   uint64
				depth uint8
				path  [][32]byte
				leaf  rawLeaf
			}
			var vs []variant
			vs = append(vs, variant{"idx+1", uint64(idx) + 1, proof.TreeDepth, path, leaves[idx]})
			vs = append(vs, variant{"idx+2^depth", uint64(idx) + 1<<proof.TreeDepth, proof.TreeDepth, path, leaves[idx]})
			if idx > 0 {
				vs = append(vs, variant{"idx-1", uint64(idx) - 1, proof.TreeDepth, path, leaves[idx]})
			}
			vs = append(vs, variant{"depth+1", uint64(idx), proof.TreeDepth + 1, path, leaves[idx]})
			if proof.TreeDepth > 0 {
				vs = append(vs, variant{"depth-1", uint64(idx), proof.TreeDepth - 1, path, leaves[idx]})
				bad := append([][32]byte(nil), path...)
				bad[r.Intn(len(bad))][r.Intn(32)] ^= 1
				vs = append(vs, variant{"sibling-flip", uint64(idx), proof.TreeDepth, bad, leaves[idx]})
				vs = append(vs, variant{"path-short", uint64(idx), proof.TreeDepth, path[:len(path)-1], leaves[idx]})
			}
			vs = append(vs, variant{"path-long", uint64(idx), proof.TreeDepth, append(append([][32]byte(nil), path...), [32]byte{}), leaves[idx]})
			other := leaves[(idx+1)%n]
			vs = append(vs, variant{"other-leaf", uint64(idx), proof.TreeDepth, path, other})
			for _, v := range vs {
				gp := &merklearray.SingleLeafProof{Proof: merklearray.Proof{HashFactory: crypto.HashFactory{HashType: crypto.Sha256}, TreeDepth: v.depth}}
				for _, p := range v.path {
					gp.Path = append(gp.Path, append(crypto.GenericDigest(nil), p[:]...))
				}
				gOK := merklearray.VerifyVectorCommitment(root, map[uint64]crypto.Hashable{v.idx: v.leaf}, gp.ToProof()) == nil
				rr, ok := RustSha256VCRoot(leafHash(v.leaf), v.idx, v.depth, v.path)
				rOK := ok && bytes.Equal(rr[:], root)
				g, rv := Verdict{Status: Rejected}, Verdict{Status: Rejected}
				if gOK {
					g.Status = Accepted
				}
				if rOK {
					rv.Status = Accepted
				}
				class := classify(g, rv, true)
				if class == ClassLiveness && int(v.depth) != len(v.path) {
					// Known, masked difference: go-algorand walks however many siblings it is
					// given and uses TreeDepth only to position the leaf, so for some indices
					// (e.g. 0) a wrong depth is harmless there; Rust requires depth == len(path).
					// The light node never takes a depth separately: it uses len(path) (and a
					// fixed 8 with an 8-sibling path for headers), which is checked next.
					recordMasked(t, "vc/depth-not-path-length", label+"-"+v.name)
				} else {
					stats.record("vc/damaged", g, rv, class)
					if class != "" {
						t.Errorf("%s divergence [vc/damaged/%s-%s]: go=%v rust=%v", class, label, v.name, gOK, rOK)
					}
				}
				// As the light node calls it: depth = number of siblings.
				gp.TreeDepth = uint8(len(v.path))
				gOK2 := merklearray.VerifyVectorCommitment(root, map[uint64]crypto.Hashable{v.idx: v.leaf}, gp.ToProof()) == nil
				rr2, ok2 := RustSha256VCRoot(leafHash(v.leaf), v.idx, uint8(len(v.path)), v.path)
				rOK2 := ok2 && bytes.Equal(rr2[:], root)
				g2, r2 := Verdict{Status: Rejected}, Verdict{Status: Rejected}
				if gOK2 {
					g2.Status = Accepted
				}
				if rOK2 {
					r2.Status = Accepted
				}
				if verbose && gOK2 && rOK2 {
					t.Logf("both accept as light node: %s", v.name)
				}
				class2 := classify(g2, r2, true)
				stats.record("vc/damaged-as-light-node", g2, r2, class2)
				if class2 != "" {
					t.Errorf("%s divergence [vc/damaged-as-light-node/%s-%s]: go=%v rust=%v", class2, label, v.name, gOK2, rOK2)
				}
			}
		}
	}
}
