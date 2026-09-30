package difftest

// Shared plumbing: run one input through go-algorand (the reference) and the Rust port,
// compare the verdicts, classify and record every divergence.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

// Case is one state proof verification: the verifier's trusted inputs and the encoded proof.
type Case struct {
	Voters   []byte   `json:"voters"`
	LnPW     uint64   `json:"lnProvenWeight"`
	Strength uint64   `json:"strengthTarget"`
	Round    uint64   `json:"round"`
	MsgHash  [32]byte `json:"msgHash"`
	Proof    []byte   `json:"proof"`
}

// Verdict of one side.
type Verdict struct {
	Status int
	Err    string
}

// GoVerify is the reference: protocol.Decode + MkVerifierWithLnProvenWeight(..).Verify.
// canonical reports whether the proof bytes are exactly go-algorand's own encoding of what
// they decode to.
func GoVerify(c *Case) (v Verdict, canonical bool) {
	var sp stateproof.StateProof
	if err := protocol.Decode(c.Proof, &sp); err != nil {
		return Verdict{DecodeFailed, err.Error()}, false
	}
	canonical = bytes.Equal(protocol.Encode(&sp), c.Proof)
	var partcom crypto.GenericDigest = append([]byte(nil), c.Voters...)
	verifier := stateproof.MkVerifierWithLnProvenWeight(partcom, c.LnPW, c.Strength)
	if err := verifier.Verify(basics.Round(c.Round), stateproof.MessageHash(c.MsgHash), &sp); err != nil {
		return Verdict{Rejected, err.Error()}, canonical
	}
	return Verdict{Accepted, ""}, canonical
}

func RustVerifyCase(c *Case) Verdict {
	st, err := RustVerify(c.Voters, c.LnPW, c.Strength, c.Round, c.MsgHash, c.Proof)
	return Verdict{st, err}
}

// Divergence classes.
const (
	// Rust accepts what go-algorand rejects: a light client could be fooled. Urgent.
	ClassSoundness = "SOUNDNESS"
	// Rust rejects a canonical proof that go-algorand accepts: a light client could stall.
	ClassLiveness = "LIVENESS"
	// The verdicts differ only on bytes that are not go-algorand's canonical encoding (the
	// Rust decoder is intentionally stricter). Real chain data is always canonical.
	ClassNonCanonical = "NON-CANONICAL"
)

func classify(g, r Verdict, canonical bool) string {
	gAcc, rAcc := g.Status == Accepted, r.Status == Accepted
	switch {
	case gAcc == rAcc:
		return ""
	case rAcc:
		// Conservative: even on non-canonical bytes, Rust accepting what Go rejects is
		// treated as a soundness divergence (the stricter Rust decoder should never do it).
		return ClassSoundness
	case !canonical:
		return ClassNonCanonical
	default:
		return ClassLiveness
	}
}

// Stats are printed at the end of the run and written to findings/summary.json.
type Stats struct {
	mu          sync.Mutex
	Compared    map[string]int
	BothAccept  map[string]int
	BothReject  map[string]int
	Divergences map[string]map[string]int
}

var stats = &Stats{
	Compared:    map[string]int{},
	BothAccept:  map[string]int{},
	BothReject:  map[string]int{},
	Divergences: map[string]map[string]int{},
}

func (s *Stats) record(group string, g, r Verdict, class string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Compared[group]++
	switch {
	case class != "":
		if s.Divergences[class] == nil {
			s.Divergences[class] = map[string]int{}
		}
		s.Divergences[class][group]++
	case g.Status == Accepted:
		s.BothAccept[group]++
	default:
		s.BothReject[group]++
	}
}

// failOnNonCanonical makes NON-CANONICAL divergences fail the run too (DIFFTEST_STRICT=1).
var failOnNonCanonical = os.Getenv("DIFFTEST_STRICT") == "1"

// CompareCase runs c through both verifiers and fails t on a divergence (saving a repro).
func CompareCase(t testing.TB, group, label string, c *Case) (Verdict, Verdict) {
	t.Helper()
	g, canonical := GoVerify(c)
	r := RustVerifyCase(c)
	class := classify(g, r, canonical)
	stats.record(group, g, r, class)
	if class != "" {
		repro := "saved to "
		path, err := saveRepro(class, group, label, c, g, r)
		if err != nil {
			repro = "NOT SAVED: " + err.Error()
		} else {
			repro += path
		}
		msg := fmt.Sprintf("%s divergence [%s/%s]: go=%d (%s) rust=%d (%s); repro %s",
			class, group, label, g.Status, g.Err, r.Status, r.Err, repro)
		if class == ClassNonCanonical && !failOnNonCanonical {
			t.Log(msg)
		} else {
			t.Error(msg)
		}
	}
	return g, r
}

// CompareValue records a primitive comparison (hashes, coins, ...).
func CompareValue(t testing.TB, group, label string, equal bool, detail func() string) {
	t.Helper()
	g := Verdict{Status: Accepted}
	r := g
	class := ""
	if !equal {
		r = Verdict{Status: Rejected}
		class = ClassSoundness // a different value is treated as the worst case
	}
	stats.record(group, g, r, class)
	if !equal {
		t.Errorf("value divergence [%s/%s]: %s", group, label, detail())
	}
}

// recordMasked counts a known component-level difference that the caller has shown cannot
// change a state proof verdict (reported in the summary, not a failure).
func recordMasked(t testing.TB, group, label string) {
	t.Helper()
	stats.mu.Lock()
	defer stats.mu.Unlock()
	stats.Compared[group]++
	if stats.Divergences["MASKED"] == nil {
		stats.Divergences["MASKED"] = map[string]int{}
	}
	stats.Divergences["MASKED"][group]++
}

// recordUpstream counts a difference inside go-algorand itself (e.g. between CPU
// architectures): reported, not a failure of the Rust port.
func recordUpstream(t testing.TB, group, detail string) {
	t.Helper()
	stats.mu.Lock()
	defer stats.mu.Unlock()
	stats.Compared[group]++
	if stats.Divergences["UPSTREAM"] == nil {
		stats.Divergences["UPSTREAM"] = map[string]int{}
	}
	stats.Divergences["UPSTREAM"][group]++
	upstreamLog = append(upstreamLog, group+": "+detail)
}

var upstreamLog []string

var reproMu sync.Mutex

// saveRepro writes the complete case (trusted inputs and proof) and both verdicts to
// findings/<class>/<group>-<label>-<hash>.json and returns the path. Group and label are
// flattened into one file name; the hash keeps distinct cases with the same label apart.
func saveRepro(class, group, label string, c *Case, g, r Verdict) (string, error) {
	reproMu.Lock()
	defer reproMu.Unlock()
	dir := filepath.Join("findings", class)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	body, err := json.MarshalIndent(map[string]any{
		"class": class, "group": group, "label": label,
		"voters": hex.EncodeToString(c.Voters), "lnProvenWeight": c.LnPW,
		"strengthTarget": c.Strength, "round": c.Round,
		"msgHash": hex.EncodeToString(c.MsgHash[:]), "proof": hex.EncodeToString(c.Proof),
		"go": g, "rust": r,
	}, "", "  ")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	name := fmt.Sprintf("%s-%s-%x.json", sanitize(group), sanitize(label), sum[:4])
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func sanitize(s string) string {
	out := []byte(s)
	for i, b := range out {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.') {
			out[i] = '_'
		}
	}
	if len(out) > 120 {
		out = out[:120]
	}
	return string(out)
}

func TestMain(m *testing.M) {
	code := m.Run()
	printSummary()
	os.Exit(code)
}

func printSummary() {
	stats.mu.Lock()
	defer stats.mu.Unlock()
	if len(stats.Compared) == 0 {
		return
	}
	groups := make([]string, 0, len(stats.Compared))
	total := 0
	for g, n := range stats.Compared {
		groups = append(groups, g)
		total += n
	}
	sort.Strings(groups)
	fmt.Printf("\n%-28s %10s %11s %11s %s\n", "group", "compared", "both accept", "both reject", "divergences")
	for _, g := range groups {
		div := ""
		for class, byGroup := range stats.Divergences {
			if n := byGroup[g]; n > 0 {
				div += fmt.Sprintf("%s=%d ", class, n)
			}
		}
		fmt.Printf("%-28s %10d %11d %11d %s\n", g, stats.Compared[g], stats.BothAccept[g], stats.BothReject[g], div)
	}
	fmt.Printf("%-28s %10d\n", "TOTAL", total)
	_ = os.MkdirAll("findings", 0o755)
	if len(upstreamLog) > 0 {
		_ = os.WriteFile(filepath.Join("findings", "upstream.txt"), []byte(strings.Join(upstreamLog, "\n")+"\n"), 0o644)
	}
	body, _ := json.MarshalIndent(stats, "", "  ")
	_ = os.WriteFile(filepath.Join("findings", "summary.json"), body, 0o644)
}

// Reproductions are saved for groups with slashes, hold the complete case, and a failed save
// is reported rather than claimed.
func TestSaveRepro(t *testing.T) {
	t.Chdir(t.TempDir())
	c := &Case{Voters: []byte{1, 2, 3}, LnPW: 4, Strength: 5, Round: 6, MsgHash: [32]byte{7}, Proof: []byte{8, 9}}
	g, r := Verdict{Rejected, "go error"}, Verdict{Accepted, ""}
	for _, group := range []string{"real/mut", "synthetic/ctx", "fuzz/bytes"} {
		path, err := saveRepro(ClassSoundness, group, "audit/label", c, g, r)
		if err != nil {
			t.Fatalf("%s: %v", group, err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: reported reproduction does not exist: %v", group, err)
		}
		var got struct {
			Class, Group, Label string
			Voters, MsgHash, Proof string
			LnProvenWeight         uint64
			StrengthTarget         uint64
			Round                  uint64
			Go, Rust               Verdict
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		voters, _ := hex.DecodeString(got.Voters)
		msgHash, _ := hex.DecodeString(got.MsgHash)
		proof, _ := hex.DecodeString(got.Proof)
		if got.Class != ClassSoundness || got.Group != group || got.Label != "audit/label" ||
			!bytes.Equal(voters, c.Voters) || !bytes.Equal(msgHash, c.MsgHash[:]) || !bytes.Equal(proof, c.Proof) ||
			got.LnProvenWeight != c.LnPW || got.StrengthTarget != c.Strength || got.Round != c.Round ||
			got.Go != g || got.Rust != r {
			t.Errorf("%s: saved reproduction is incomplete:\n%s", group, raw)
		}
	}
	// A different case with the same group and label does not overwrite the first.
	c2 := *c
	c2.Proof = []byte{10}
	p1, _ := saveRepro(ClassSoundness, "real/mut", "audit/label", c, g, r)
	p2, _ := saveRepro(ClassSoundness, "real/mut", "audit/label", &c2, g, r)
	if p1 == p2 {
		t.Errorf("distinct cases share %s", p1)
	}
	// Unwritable destination: a file where the class directory should be.
	t.Chdir(t.TempDir())
	if err := os.WriteFile("findings", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if path, err := saveRepro(ClassSoundness, "real/mut", "audit", c, g, r); err == nil {
		t.Errorf("save into an unwritable destination reported success (%s)", path)
	}
}
