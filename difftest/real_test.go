package difftest

// Real chain data: the repo's MainNet fixture and, when fetched (./fetch-corpus.sh), a sample of
// state proofs from across MainNet and TestNet history. Every real proof must be accepted by
// both verifiers, and every structured mutation of it must get the same verdict from both.

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/protocol"
)

// RealProof is one state proof from the chain with the trusted inputs that verify it.
type RealProof struct {
	Network        string `json:"network"`
	ConfirmedRound uint64 `json:"confirmedRound"`
	// Trusted inputs: from the previous interval's message (or the network's first voters).
	Voters []byte `json:"voters"`
	LnPW   uint64 `json:"lnProvenWeight"`
	// The interval's message and its proof, as in the block.
	Message    stateproofmsg.Message `json:"-"`
	MessageRaw []byte                `json:"message"` // msgpack as in the block
	Proof      []byte                `json:"proof"`
}

func (p *RealProof) Case() *Case {
	h := p.Message.Hash()
	return &Case{
		Voters:   p.Voters,
		LnPW:     p.LnPW,
		Strength: 256, // config.Consensus[*].StateProofStrengthTarget since v34
		Round:    uint64(p.Message.LastAttestedRound),
		MsgHash:  [32]byte(h),
		Proof:    p.Proof,
	}
}

type fixtureInput struct {
	TrustedState struct {
		VotersCommitment string `json:"votersCommitment"`
		LnProvenWeight   uint64 `json:"lnProvenWeight"`
	} `json:"trustedState"`
	StateProofs []struct {
		ConfirmedRound uint64 `json:"confirmedRound"`
		Message        struct {
			BlockHeadersCommitment string `json:"blockHeadersCommitment"`
			VotersCommitment       string `json:"votersCommitment"`
			LnProvenWeight         uint64 `json:"lnProvenWeight"`
			FirstAttestedRound     uint64 `json:"firstAttestedRound"`
			LastAttestedRound      uint64 `json:"lastAttestedRound"`
		} `json:"message"`
		StateProof string `json:"stateProof"`
	} `json:"stateProofs"`
}

func unhex(t testing.TB, s string) []byte {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fixtureProofs loads ../fixtures/mainnet/input.json (three consecutive recent intervals).
func fixtureProofs(t testing.TB) []RealProof {
	raw, err := os.ReadFile(filepath.Join("..", "fixtures", "mainnet", "input.json"))
	if err != nil {
		t.Fatal(err)
	}
	var in fixtureInput
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	voters, lnPW := unhex(t, in.TrustedState.VotersCommitment), in.TrustedState.LnProvenWeight
	var out []RealProof
	for _, sp := range in.StateProofs {
		proof, err := base64.StdEncoding.DecodeString(sp.StateProof)
		if err != nil {
			t.Fatal(err)
		}
		msg := stateproofmsg.Message{
			BlockHeadersCommitment: unhex(t, sp.Message.BlockHeadersCommitment),
			VotersCommitment:       unhex(t, sp.Message.VotersCommitment),
			LnProvenWeight:         sp.Message.LnProvenWeight,
			FirstAttestedRound:     basics.Round(sp.Message.FirstAttestedRound),
			LastAttestedRound:      basics.Round(sp.Message.LastAttestedRound),
		}
		out = append(out, RealProof{
			Network: "mainnet", ConfirmedRound: sp.ConfirmedRound,
			Voters: voters, LnPW: lnPW, Message: msg, Proof: proof,
		})
		voters, lnPW = msg.VotersCommitment, msg.LnProvenWeight
	}
	return out
}

// corpusProofs loads corpus/*.jsonl written by cmd/fetchcorpus (empty if not fetched).
func corpusProofs(t testing.TB) []RealProof {
	files, _ := filepath.Glob(filepath.Join("corpus", "*.jsonl"))
	var out []RealProof
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 64<<20), 64<<20)
		for sc.Scan() {
			var p RealProof
			if err := json.Unmarshal(sc.Bytes(), &p); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			if err := decodeMessage(p.MessageRaw, &p.Message); err != nil {
				t.Fatalf("%s: message: %v", f, err)
			}
			out = append(out, p)
		}
		fh.Close()
		if err := sc.Err(); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func allRealProofs(t testing.TB) []RealProof {
	return append(fixtureProofs(t), corpusProofs(t)...)
}

// Every real proof verifies on both sides, and both hash its message the same way.
func TestRealProofsVerify(t *testing.T) {
	proofs := allRealProofs(t)
	t.Logf("%d real proofs (%d from corpus/)", len(proofs), len(proofs)-3)
	for _, p := range proofs {
		label := fmt.Sprintf("%s-%d", p.Network, p.Message.FirstAttestedRound)
		g, r := CompareCase(t, "real", label, p.Case())
		if g.Status != Accepted || r.Status != Accepted {
			t.Errorf("%s: real proof not accepted: go=%v rust=%v", label, g, r)
		}
		goHash := p.Message.Hash()
		rustHash := RustMsgHash(p.Message.BlockHeadersCommitment, p.Message.VotersCommitment,
			p.Message.LnProvenWeight, uint64(p.Message.FirstAttestedRound), uint64(p.Message.LastAttestedRound))
		CompareValue(t, "real/msg-hash", label, goHash == stateproof.MessageHash(rustHash), func() string {
			return fmt.Sprintf("go %x rust %x", goHash, rustHash)
		})
		if len(p.MessageRaw) > 0 {
			rh, ok, err := RustMsgDecodeHash(p.MessageRaw)
			CompareValue(t, "real/msg-decode-hash", label, ok && rh == [32]byte(goHash), func() string {
				return fmt.Sprintf("go %x rust %x ok=%v err=%s", goHash, rh, ok, err)
			})
		}
	}
}

// Every structured mutation of every real proof gets the same verdict from both sides.
func TestRealProofsMutated(t *testing.T) {
	proofs := allRealProofs(t)
	draws := envInt("DIFFTEST_DRAWS", 3)
	max := envInt("DIFFTEST_MAX_REAL_MUTATED", 40)
	for i, p := range proofs {
		if i >= max {
			break
		}
		p := p
		label := fmt.Sprintf("%s-%d", p.Network, p.Message.FirstAttestedRound)
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			mutateAndCompare(t, "real", label, p.Case(), draws, int64(p.Message.FirstAttestedRound))
		})
	}
}

func decodeMessage(raw []byte, m *stateproofmsg.Message) error {
	return protocol.Decode(raw, m)
}
