# Results

Run on 2026-09-29, Apple M3 Pro (arm64; the amd64 reference for ln ran under Rosetta), against
go-algorand `v5.0.2-stable` (fe1308bd). Command:

```bash
DIFFTEST_SYNTH=300 DIFFTEST_DRAWS=4 DIFFTEST_MAX_REAL_MUTATED=1000 ./run.sh -v
```

Corpus: 195 real state proofs (the repo fixture, and ./fetch-corpus.sh: 151 from MainNet
including its first state proof, 41 from TestNet, sampled across history) and 387 real blocks.
Synthetic: 169 proofs from go-algorand's prover (131 configurations were declined by the prover,
mostly for needing more than 640 reveals).

**41,231,988 comparisons. No SOUNDNESS, LIVENESS or NON-CANONICAL divergence.**

| group | compared | both accept | both reject | other |
|---|---:|---:|---:|---|
| real (state proof verdict) | 195 | 195 | 0 | |
| real/mut (structured mutations) | 81,842 | 72 | 81,770 | |
| real/ctx (verifier-input mutations) | 14,820 | 3,468 | 11,352 | |
| real/msg-hash, msg-decode-hash | 387 | 387 | 0 | |
| synthetic | 169 | 169 | 0 | |
| synthetic/mut | 70,025 | 193 | 69,832 | |
| synthetic/ctx | 12,844 | 2,872 | 9,972 | |
| block/light-header-seed (v34–v38) | 81 | 81 | 0 | |
| block/light-header-blockhash (v39+) | 234 | 234 | 0 | |
| block/light-header-before-state-proofs | 72 | | | MASKED 72 (out of domain, see README) |
| block/stpf-extract | 193 | 193 | 0 | |
| vc/honest | 4,279 | 4,279 | 0 | |
| vc/damaged | 38,386 | 1 | 38,385 | |
| vc/damaged-as-light-node | 38,467 | 8,558 | 29,909 | |
| vc/depth-not-path-length | 81 | | | MASKED 81 (see README) |
| weights | 440,677 | 440,677 | 0 | |
| coins | 3,000 | 3,000 | 0 | |
| sumhash512 | 5,000 | 5,000 | 0 | |
| falcon/verify, falcon/pk | 10,644 | 10,644 | 0 | |
| falcon/to-ct | 9,324 | 9,324 | 0 | |
| falcon/to-ct-trailing-bytes | 720 | | | MASKED 720 (see README) |
| msg-hash/fields, msg-hash/decode | 10,000 | 10,000 | 0 | |
| light-header-leaf, txn-leaf | 25,000 | 25,000 | 0 | |
| ln-int-approx (vs amd64 go-algorand) | 20,182,375 | 20,182,375 | 0 | after the fix; 1,132 differed before |
| proven-weight | 100,000 | 100,000 | 0 | |
| go-algorand ln, amd64 vs arm64 | 20,182,375 | | | UPSTREAM 60 (below) |

("both accept" for mutations: mutations that leave a proof valid, e.g. a lower strength target.)

The two ln rows were re-run after the input generator was fixed to cover [2^63, 2^64) (it had
dropped nearly all candidates there, see #4); the 317,982 added inputs changed nothing.

Fuzzing (coverage-guided, `go test -fuzz`): FuzzFalcon 21.3M executions in 15 min, no divergence.
State proof fuzzing: see below.

## Upstream: go-algorand's LnIntApproximation differs between amd64 and arm64

For these 60 inputs x, `stateproof.LnIntApproximation(x)` (`ceil(math.Log(float64(x))·2^16)`)
returns different values on amd64 (Go's assembly `math.Log`) and arm64 (pure Go, with fused
multiply-adds). go-algorand computes it in consensus (`stateproofMessageGenerator.go`,
`crypto/stateproof/verifier.go` via `stateproof/verify.ValidateStateProof`), so nodes on the
two architectures would disagree on a state proof whose proven weight is one of them.

```
x=21834405086772 amd64=2012906 arm64=2012907
x=22614293351678 amd64=2015206 arm64=2015207
x=22748576356715 amd64=2015594 arm64=2015595
x=43758127649686 amd64=2058466 arm64=2058467
x=44976637608938 amd64=2060266 arm64=2060267
x=80590428152565 amd64=2098489 arm64=2098490
x=93102171835889 amd64=2107947 arm64=2107948
x=101152474861467 amd64=2113383 arm64=2113382
x=103020120997507 amd64=2114581 arm64=2114582
x=103289277546087 amd64=2114752 arm64=2114753
x=114661003878382 amd64=2121597 arm64=2121598
x=115757960877319 amd64=2122221 arm64=2122222
x=150328588546816 amd64=2139347 arm64=2139348
x=165229667120355 amd64=2145542 arm64=2145541
x=174028018276538 amd64=2148941 arm64=2148942
x=228364908732758 amd64=2166750 arm64=2166749
x=320399249667353 amd64=2188941 arm64=2188942
x=324161175374446 amd64=2189706 arm64=2189707
x=344994068425918 amd64=2193789 arm64=2193788
x=361986771467695 amd64=2196939 arm64=2196940
x=363941820397898 amd64=2197292 arm64=2197293
x=375271186276131 amd64=2199302 arm64=2199301
x=379266273738148 amd64=2199996 arm64=2199995
x=388527002980637 amd64=2201577 arm64=2201576
x=392819021713609 amd64=2202296 arm64=2202297
x=413313566252310 amd64=2205629 arm64=2205630
x=413439718791163 amd64=2205649 arm64=2205650
x=432481870471749 amd64=2208601 arm64=2208600
x=450169980721046 amd64=2211228 arm64=2211227
x=481644564095215 amd64=2215657 arm64=2215656
x=660382502310876 amd64=2236340 arm64=2236341
x=661078156432507 amd64=2236410 arm64=2236409
x=680026215676025 amd64=2238261 arm64=2238262
x=684669862693504 amd64=2238707 arm64=2238708
x=704197402446812 amd64=2240550 arm64=2240551
x=708314054736692 amd64=2240932 arm64=2240933
x=730530779060182 amd64=2242957 arm64=2242956
x=738375510406736 amd64=2243656 arm64=2243657
x=741684048679402 amd64=2243950 arm64=2243949
x=754134459943246 amd64=2245041 arm64=2245040
x=755228434627966 amd64=2245135 arm64=2245136
x=756439410960313 amd64=2245241 arm64=2245240
x=764795721068215 amd64=2245960 arm64=2245961
x=769842004605728 amd64=2246392 arm64=2246391
x=780106098285427 amd64=2247259 arm64=2247260
x=787268963934234 amd64=2247858 arm64=2247859
x=788928472951552 amd64=2247997 arm64=2247996
x=789675187884353 amd64=2248059 arm64=2248058
x=837429873157074 amd64=2251906 arm64=2251907
x=844178233721638 amd64=2252433 arm64=2252432
x=844281289112308 amd64=2252440 arm64=2252441
x=845996429335981 amd64=2252573 arm64=2252574
x=887544138992246 amd64=2255716 arm64=2255715
x=900242513801357 amd64=2256647 arm64=2256646
x=902456826910839 amd64=2256808 arm64=2256807
x=909187989674563 amd64=2257295 arm64=2257294
x=919989433685528 amd64=2258069 arm64=2258068
x=931899842733299 amd64=2258912 arm64=2258911
x=961129478605491 amd64=2260935 arm64=2260936
x=966984175840230 amd64=2261334 arm64=2261333
```
