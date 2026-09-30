package difftest

/*
#cgo LDFLAGS: ${SRCDIR}/rustffi/target/release/libaln_difftest.a -ldl -lm -framework Security -framework CoreFoundation
#include <stdint.h>
#include <stddef.h>
size_t  aln_last_error(uint8_t* buf, size_t cap);
int32_t aln_sp_verify(const uint8_t* voters, size_t voters_len, uint64_t ln_pw, uint64_t strength, uint64_t round, const uint8_t* msg_hash, const uint8_t* sp, size_t sp_len);
int32_t aln_sp_decode(const uint8_t* sp, size_t sp_len);
int32_t aln_msg_decode_hash(const uint8_t* msg, size_t len, uint8_t* out);
void    aln_msg_hash(const uint8_t* bhc, size_t bhc_len, const uint8_t* voters, size_t voters_len, uint64_t ln_pw, uint64_t first, uint64_t last, uint8_t* out);
int32_t aln_verify_weights(uint64_t signed_weight, uint64_t ln_pw, uint64_t num_reveals, uint64_t strength);
void    aln_coins(const uint8_t* voters, size_t voters_len, uint64_t ln_pw, const uint8_t* sig_commit, size_t sig_commit_len, uint64_t signed_weight, const uint8_t* msg_hash, size_t n, uint64_t* out);
void    aln_sumhash512(const uint8_t* data, size_t len, uint8_t* out);
int32_t aln_falcon_verify(const uint8_t* pk, size_t pk_len, const uint8_t* sig, size_t sig_len, const uint8_t* msg, size_t msg_len);
int32_t aln_falcon_to_ct(const uint8_t* sig, size_t sig_len, uint8_t* out);
void    aln_light_header_leaf(const uint8_t* seed, const uint8_t* block_hash, uint64_t round, const uint8_t* gh, const uint8_t* tc, uint8_t* out);
void    aln_txn_leaf(const uint8_t* txn, size_t txn_len, const uint8_t* stib, size_t stib_len, uint8_t* out);
int32_t aln_ln_int_approximation(uint64_t x, uint64_t* out);
uint64_t aln_proven_weight(uint64_t total);
int32_t aln_sha256_vc_root(const uint8_t* leaf, uint64_t index, uint8_t depth, const uint8_t* siblings, size_t n, uint8_t* out);
int32_t aln_block_light_header_leaf(const uint8_t* block, size_t len, uint8_t* out);
int32_t aln_block_stpf(const uint8_t* block, size_t len, uint64_t first, uint8_t* out_msg_hash, uint8_t* out_proof_sha256);
*/
import "C"

import "unsafe"

// Status of a verification on either side.
const (
	Accepted     = 0
	DecodeFailed = 1
	Rejected     = 2
)

func ptr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func rustLastError() string {
	n := C.aln_last_error(nil, 0)
	buf := make([]byte, n)
	C.aln_last_error(ptr(buf), C.size_t(len(buf)))
	return string(buf)
}

// RustVerify runs the Rust decoder and verifier; returns a status and the Rust error text.
func RustVerify(voters []byte, lnPW, strength, round uint64, msgHash [32]byte, sp []byte) (int, string) {
	st := int(C.aln_sp_verify(ptr(voters), C.size_t(len(voters)), C.uint64_t(lnPW), C.uint64_t(strength),
		C.uint64_t(round), ptr(msgHash[:]), ptr(sp), C.size_t(len(sp))))
	if st != Accepted {
		return st, rustLastError()
	}
	return st, ""
}

func RustDecode(sp []byte) (bool, string) {
	if C.aln_sp_decode(ptr(sp), C.size_t(len(sp))) == 0 {
		return true, ""
	}
	return false, rustLastError()
}

func RustMsgDecodeHash(msg []byte) ([32]byte, bool, string) {
	var out [32]byte
	if C.aln_msg_decode_hash(ptr(msg), C.size_t(len(msg)), ptr(out[:])) != 0 {
		return out, false, rustLastError()
	}
	return out, true, ""
}

func RustMsgHash(bhc, voters []byte, lnPW, first, last uint64) [32]byte {
	var out [32]byte
	C.aln_msg_hash(ptr(bhc), C.size_t(len(bhc)), ptr(voters), C.size_t(len(voters)), C.uint64_t(lnPW),
		C.uint64_t(first), C.uint64_t(last), ptr(out[:]))
	return out
}

func RustVerifyWeights(signed, lnPW, numReveals, strength uint64) bool {
	return C.aln_verify_weights(C.uint64_t(signed), C.uint64_t(lnPW), C.uint64_t(numReveals), C.uint64_t(strength)) == 0
}

func RustCoins(voters []byte, lnPW uint64, sigCommit []byte, signed uint64, msgHash [32]byte, n int) []uint64 {
	out := make([]uint64, n)
	if n == 0 {
		return out
	}
	C.aln_coins(ptr(voters), C.size_t(len(voters)), C.uint64_t(lnPW), ptr(sigCommit), C.size_t(len(sigCommit)),
		C.uint64_t(signed), ptr(msgHash[:]), C.size_t(n), (*C.uint64_t)(unsafe.Pointer(&out[0])))
	return out
}

func RustSumhash512(data []byte) [64]byte {
	var out [64]byte
	C.aln_sumhash512(ptr(data), C.size_t(len(data)), ptr(out[:]))
	return out
}

func RustFalconVerify(pk, sig, msg []byte) bool {
	return C.aln_falcon_verify(ptr(pk), C.size_t(len(pk)), ptr(sig), C.size_t(len(sig)), ptr(msg), C.size_t(len(msg))) == 0
}

func RustFalconToCT(sig []byte) ([]byte, bool) {
	out := make([]byte, 1538)
	if C.aln_falcon_to_ct(ptr(sig), C.size_t(len(sig)), ptr(out)) != 0 {
		return nil, false
	}
	return out, true
}

func RustLightHeaderLeaf(seed, blockHash [32]byte, round uint64, gh, tc [32]byte) [32]byte {
	var out [32]byte
	C.aln_light_header_leaf(ptr(seed[:]), ptr(blockHash[:]), C.uint64_t(round), ptr(gh[:]), ptr(tc[:]), ptr(out[:]))
	return out
}

func RustTxnLeaf(txn, stib []byte) [32]byte {
	var out [32]byte
	C.aln_txn_leaf(ptr(txn), C.size_t(len(txn)), ptr(stib), C.size_t(len(stib)), ptr(out[:]))
	return out
}

func RustLnIntApproximation(x uint64) (uint64, bool) {
	var out C.uint64_t
	if C.aln_ln_int_approximation(C.uint64_t(x), &out) != 0 {
		return 0, false
	}
	return uint64(out), true
}

func RustProvenWeight(total uint64) uint64 {
	return uint64(C.aln_proven_weight(C.uint64_t(total)))
}

// RustSha256VCRoot recomputes a SHA-256 vector commitment root from a single-leaf path.
func RustSha256VCRoot(leaf [32]byte, index uint64, depth uint8, siblings [][32]byte) ([32]byte, bool) {
	var out [32]byte
	flat := make([]byte, 0, 32*len(siblings))
	for _, s := range siblings {
		flat = append(flat, s[:]...)
	}
	ok := C.aln_sha256_vc_root(ptr(leaf[:]), C.uint64_t(index), C.uint8_t(depth), ptr(flat), C.size_t(len(siblings)), ptr(out[:])) == 0
	return out, ok
}

func RustBlockLightHeaderLeaf(block []byte) ([32]byte, bool, string) {
	var out [32]byte
	if C.aln_block_light_header_leaf(ptr(block), C.size_t(len(block)), ptr(out[:])) != 0 {
		return out, false, rustLastError()
	}
	return out, true, ""
}

// RustBlockStpf returns the message hash and proof SHA-256 of the state proof transaction for
// the interval starting at first, as the light node extracts it from a raw block.
func RustBlockStpf(block []byte, first uint64) (msgHash, proofHash [32]byte, status int) {
	st := C.aln_block_stpf(ptr(block), C.size_t(len(block)), C.uint64_t(first), ptr(msgHash[:]), ptr(proofHash[:]))
	return msgHash, proofHash, int(st)
}
