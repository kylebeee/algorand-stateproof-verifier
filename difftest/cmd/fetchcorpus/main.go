// fetchcorpus samples real state proofs and blocks from an algod node for the differential
// tests, decoding everything with go-algorand itself (the reference):
//
//	corpus/<network>.jsonl        one state proof per line, with the trusted inputs that verify it
//	corpus/<network>-blocks/*.bin raw blocks (msgpack as algod serves them): the blocks carrying
//	                              those proofs, plus random blocks from across history
//
// Usage: ALGOD_TOKEN=... go run ./cmd/fetchcorpus -network mainnet -samples 150 -blocks 150
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
)

type network struct {
	algod            string
	firstVotersRound uint64
}

var networks = map[string]network{
	"mainnet": {"https://mainnet-api.4160.nodely.dev", 23_591_680},
	"testnet": {"https://testnet-api.4160.nodely.dev", 24_098_560},
}

const interval = 256

type realProof struct {
	Network        string `json:"network"`
	ConfirmedRound uint64 `json:"confirmedRound"`
	Voters         []byte `json:"voters"`
	LnPW           uint64 `json:"lnProvenWeight"`
	MessageRaw     []byte `json:"message"`
	Proof          []byte `json:"proof"`
}

var (
	algod  string
	token  = os.Getenv("ALGOD_TOKEN")
	client = &http.Client{Timeout: 2 * time.Minute}
)

func get(path string) ([]byte, error) {
	var last error
	for attempt := 0; attempt < 6; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(1<<attempt) * time.Second)
		}
		req, _ := http.NewRequest("GET", algod+path, nil)
		if token != "" {
			req.Header.Set("X-Algo-API-Token", token)
		}
		resp, err := client.Do(req)
		if err != nil {
			last = err
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			last = err
			continue
		}
		if resp.StatusCode != 200 {
			last = fmt.Errorf("GET %s: HTTP %d: %s", path, resp.StatusCode, bytes.TrimSpace(body))
			if resp.StatusCode < 500 && resp.StatusCode != 429 {
				return nil, last
			}
			continue
		}
		return body, nil
	}
	return nil, last
}

func block(round uint64, headerOnly bool) ([]byte, *rpcs.EncodedBlockCert) {
	path := fmt.Sprintf("/v2/blocks/%d?format=msgpack", round)
	if headerOnly {
		path += "&header-only=true"
	}
	raw, err := get(path)
	if err != nil {
		log.Fatal(err)
	}
	var b rpcs.EncodedBlockCert
	if err := protocol.Decode(raw, &b); err != nil {
		log.Fatalf("block %d: %v", round, err)
	}
	return raw, &b
}

func lastRound() uint64 {
	raw, err := get("/v2/status")
	if err != nil {
		log.Fatal(err)
	}
	var s struct {
		LastRound uint64 `json:"last-round"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		log.Fatal(err)
	}
	return s.LastRound
}

// nextProofRound is spt[0].n of block r (the next interval end the chain expects a proof for).
func nextProofRound(r uint64) uint64 {
	_, b := block(r, true)
	return uint64(b.Block.StateProofTracking[protocol.StateProofBasic].StateProofNextRound)
}

// proofBlock finds the block carrying the state proof of the interval ending at last: the first
// block whose header expects a proof beyond it.
func proofBlock(last, guess, tip uint64) uint64 {
	if guess > last && guess <= tip && nextProofRound(guess) > last && nextProofRound(guess-1) <= last {
		return guess
	}
	lo, hi := last, last+interval/2
	for nextProofRound(hi) <= last {
		lo, hi = hi, hi+interval
		if hi > tip {
			log.Fatalf("no state proof for the interval ending at %d yet", last)
		}
	}
	for hi-lo > 1 {
		mid := (lo + hi) / 2
		if nextProofRound(mid) > last {
			hi = mid
		} else {
			lo = mid
		}
	}
	return hi
}

// stateProofTxn returns the stpf transaction for the interval starting at first in block r.
func stateProofTxn(r, first uint64) ([]byte, stateproofmsg.Message, stateproof.StateProof) {
	raw, b := block(r, false)
	txns, err := b.Block.DecodePaysetFlat()
	if err != nil {
		log.Fatal(err)
	}
	for _, t := range txns {
		if t.Txn.Type == protocol.StateProofTx && uint64(t.Txn.Message.FirstAttestedRound) == first {
			return raw, t.Txn.Message, t.Txn.StateProof
		}
	}
	log.Fatalf("block %d has no state proof for round %d", r, first)
	return nil, stateproofmsg.Message{}, stateproof.StateProof{}
}

func main() {
	net := flag.String("network", "mainnet", "mainnet or testnet")
	samples := flag.Int("samples", 150, "state proofs to sample (plus the first one)")
	blocks := flag.Int("blocks", 150, "extra random blocks (header-only) to sample")
	seed := flag.Int64("seed", 1, "sampling seed")
	flag.Parse()
	n, ok := networks[*net]
	if !ok {
		log.Fatalf("unknown network %s", *net)
	}
	algod = n.algod
	if v := os.Getenv("ALGOD_URL"); v != "" {
		algod = v
	}
	tip := lastRound()
	anchorNext := n.firstVotersRound + 1
	intervals := (tip - anchorNext - 2*interval) / interval
	r := rand.New(rand.NewSource(*seed))

	blockDir := filepath.Join("corpus", *net+"-blocks")
	if err := os.MkdirAll(blockDir, 0o755); err != nil {
		log.Fatal(err)
	}
	out, err := os.Create(filepath.Join("corpus", *net+".jsonl"))
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()
	enc := json.NewEncoder(out)

	idx := []uint64{0}
	for len(idx) < *samples+1 {
		idx = append(idx, 1+uint64(r.Int63n(int64(intervals-1))))
	}
	offset := uint64(146)
	for i, k := range idx {
		first := anchorNext + k*interval
		var voters []byte
		var lnPW uint64
		if k == 0 {
			// The network's first voters: spt[0] of the header that commits to them.
			_, hb := block(n.firstVotersRound, true)
			spt := hb.Block.StateProofTracking[protocol.StateProofBasic]
			voters = spt.StateProofVotersCommitment
			proto := config.Consensus[hb.Block.CurrentProtocol]
			proven, overflow := basics.Muldiv(spt.StateProofOnlineTotalWeight.ToUint64(), uint64(proto.StateProofWeightThreshold), 1<<32)
			if overflow {
				log.Fatal("proven weight overflow")
			}
			if lnPW, err = stateproof.LnIntApproximation(proven); err != nil {
				log.Fatal(err)
			}
		} else {
			prevLast := first - 1
			pr := proofBlock(prevLast, prevLast+offset, tip)
			_, msg, _ := stateProofTxn(pr, first-interval)
			voters, lnPW = msg.VotersCommitment, msg.LnProvenWeight
		}
		last := first + interval - 1
		pr := proofBlock(last, last+offset, tip)
		offset = pr - last
		raw, msg, sp := stateProofTxn(pr, first)
		if err := os.WriteFile(filepath.Join(blockDir, fmt.Sprintf("%d.bin", pr)), raw, 0o644); err != nil {
			log.Fatal(err)
		}
		if err := enc.Encode(realProof{*net, pr, voters, lnPW, protocol.Encode(&msg), protocol.Encode(&sp)}); err != nil {
			log.Fatal(err)
		}
		log.Printf("%s %d/%d: interval %d (proof in block %d)", *net, i+1, len(idx), first, pr)
	}
	// Random header-only blocks from genesis to the tip (both light header eras).
	for i := 0; i < *blocks; i++ {
		round := 1 + uint64(r.Int63n(int64(tip-1)))
		raw, _ := block(round, true)
		if err := os.WriteFile(filepath.Join(blockDir, fmt.Sprintf("h%d.bin", round)), raw, 0o644); err != nil {
			log.Fatal(err)
		}
	}
	log.Printf("wrote %d proofs and %d extra headers", len(idx), *blocks)
}
