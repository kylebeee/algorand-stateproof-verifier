// lnref evaluates go-algorand's stateproof.LnIntApproximation formula,
// ceil(math.Log(float64(x)) * 2^16), for each x on stdin (one per line). The difftest builds it
// for GOARCH=amd64 as the reference MainNet's amd64 nodes compute (Go's math.Log is assembly on
// amd64 and uses fused multiply-adds on arm64, so the architectures can disagree). It has no
// go-algorand dependency so it cross-builds without cgo; TestLnIntApproximation checks that
// this formula equals stateproof.LnIntApproximation on the native architecture.
package main

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"strconv"
)

func main() {
	in := bufio.NewScanner(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	precision := uint64(1 << 16)
	for in.Scan() {
		x, err := strconv.ParseUint(in.Text(), 10, 64)
		if err != nil || x == 0 {
			fmt.Fprintln(out, "err")
			continue
		}
		fmt.Fprintln(out, uint64(math.Ceil(math.Log(float64(x))*float64(precision))))
	}
}
