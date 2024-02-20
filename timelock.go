package timelock

import (
	"bytes"
	"errors"
	"io"
	"math/big"
	"slices"
	"strconv"

	tz "github.com/ecadlabs/gotez/v2"
	"golang.org/x/crypto/blake2b"
)

var rsaModulus *big.Int

func init() {
	rsaModulus, _ = new(big.Int).SetString("25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357", 10)
}

var (
	two = big.NewInt(2)
	one = big.NewInt(1)
)

type VDFTuple struct {
	LockedValue   tz.BigUint `json:"locked_value"`
	UnlockedValue tz.BigUint `json:"unlocked_value"`
	VDFProof      tz.BigUint `json:"vdf_proof"`
}

type TimelockProof struct {
	VDFTuple VDFTuple   `json:"vdf_tuple"`
	Nonce    tz.BigUint `json:"nonce"`
}

func nextPrime(n *big.Int) *big.Int {
	p := new(big.Int)
	if n.Cmp(two) < 0 {
		return p.Set(two)
	}
	p.Add(n, one)
	limit := new(big.Int).Mul(n, two)
	for p.Cmp(limit) < 0 {
		// use 25 bases like in GMP mpz_nextprime and thus in Tezos
		if p.ProbablyPrime(25) {
			break
		}
		p.Add(p, one)
	}
	return p
}

func randomInt(r io.Reader, bitLen int) (*big.Int, error) {
	sz := bitLen / 8
	bytes := make([]byte, sz)
	if _, err := io.ReadFull(r, bytes); err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(bytes), nil
}

func generate(r io.Reader, mod *big.Int) (*big.Int, error) {
	x, err := randomInt(r, mod.BitLen())
	if err != nil {
		return nil, err
	}
	m := new(big.Int).Sub(mod, two)
	x.Mod(x, m)
	x.Add(x, two)
	return x, nil
}

func intBytes(x *big.Int) []byte {
	b := x.Bytes()
	slices.Reverse(b)
	return b
}

var hashSeparator = []byte{0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00}

func hashToPrime(time int, value, key, mod *big.Int) *big.Int {
	var b bytes.Buffer
	b.Write([]byte(strconv.FormatInt(int64(time), 10)))
	b.Write(hashSeparator)
	b.Write(intBytes(mod))
	b.Write(hashSeparator)
	b.Write(intBytes(value))
	b.Write(hashSeparator)
	b.Write(intBytes(key))

	h, _ := blake2b.New(32, []byte{32})
	h.Write(b.Bytes())
	sum := h.Sum(nil)

	slices.Reverse(sum)
	val := new(big.Int).SetBytes(sum)
	return nextPrime(val)
}

func proveWesolowski(time int, locked, unlocked, mod *big.Int) *big.Int {
	l := hashToPrime(time, locked, unlocked, mod)
	pi, r := big.NewInt(1), big.NewInt(1)
	for ; time > 0; time -= 1 {
		var rr big.Int
		rr.Lsh(r, 1)
		r.Mod(&rr, l)
		var pi2 big.Int
		pi2.Mul(pi, pi)
		pi2.Mod(&pi2, mod)
		if rr.Cmp(l) >= 0 {
			pi.Mul(&pi2, locked)
		} else {
			pi.Set(&pi2)
		}
	}
	return pi.Mod(pi, mod)
}

func mustNewBigUint(x *big.Int) tz.BigUint {
	out, err := tz.NewBigUint(x)
	if err != nil {
		panic(err.Error())
	}
	return out
}

func newBigUintUnsafe(x *big.Int) tz.BigUint {
	out, _ := tz.NewBigUint(x)
	return out
}

func Prove(time int, locked, unlocked, mod *big.Int) *TimelockProof {
	if mod == nil {
		mod = rsaModulus
	}
	return &TimelockProof{
		VDFTuple: VDFTuple{
			LockedValue:   mustNewBigUint(locked),
			UnlockedValue: mustNewBigUint(unlocked),
			VDFProof:      newBigUintUnsafe(proveWesolowski(time, locked, unlocked, mod)),
		},
		Nonce: tz.NewBigUint64(1),
	}
}

func unlockTimelock(time int, locked, mod *big.Int) *big.Int {
	x := new(big.Int).Set(locked)
	if locked.Cmp(one) <= 0 {
		return x
	}
	for ; time > 0; time -= 1 {
		x.Mul(x, x)
		x.Mod(x, mod)
	}
	return x
}

func UnlockAndProve(time int, locked, mod *big.Int) *TimelockProof {
	if mod == nil {
		mod = rsaModulus
	}
	unlocked := unlockTimelock(time, locked, mod)
	return Prove(time, locked, unlocked, mod)
}

func PrecomputeTimelock(random io.Reader, time int, mod *big.Int) (*VDFTuple, error) {
	if mod == nil {
		mod = rsaModulus
	}
	locked, err := generate(random, mod)
	if err != nil {
		return nil, err
	}
	unlocked := unlockTimelock(time, locked, mod)
	return &VDFTuple{
		LockedValue:   newBigUintUnsafe(locked),
		UnlockedValue: newBigUintUnsafe(unlocked),
		VDFProof:      newBigUintUnsafe(proveWesolowski(time, locked, unlocked, mod)),
	}, nil
}

func (vdfTuple *VDFTuple) verifyWesolowski(time int, mod *big.Int) bool {
	lockedValue := vdfTuple.LockedValue.Int()
	unlockedValue := vdfTuple.UnlockedValue.Int()
	l := hashToPrime(time, lockedValue, unlockedValue, mod)
	r := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(time)), l)
	ll := new(big.Int).Exp(vdfTuple.VDFProof.Int(), l, mod)
	rr := new(big.Int).Exp(lockedValue, r, mod)
	unlocked := new(big.Int).Mul(ll, rr)
	unlocked.Mod(unlocked, mod)
	return unlocked.Cmp(unlockedValue) == 0
}

func Verify(locked *big.Int, proof *TimelockProof, time int, mod *big.Int) bool {
	if mod == nil {
		mod = rsaModulus
	}
	randomizedChallenge := new(big.Int).Exp(proof.VDFTuple.LockedValue.Int(), proof.Nonce.Int(), mod)
	return randomizedChallenge.Cmp(locked) == 0 && proof.VDFTuple.verifyWesolowski(time, mod)
}

var (
	ErrInvalidArgument = errors.New("invalid argument")
	ErrVerification    = errors.New("timelock tuple verification failed")
)

func (v *VDFTuple) Proof(random io.Reader, time int, mod *big.Int) (locked *big.Int, proof *TimelockProof, err error) {
	if mod == nil {
		mod = rsaModulus
	}
	lockedValue := v.LockedValue.Int()
	unlockedValue := v.UnlockedValue.Int()
	vdfProof := v.VDFProof.Int()
	if lockedValue.Cmp(one) < 1 ||
		unlockedValue.Sign() < 1 ||
		vdfProof.Sign() < 1 ||
		lockedValue.Cmp(mod) > 0 ||
		unlockedValue.Cmp(mod) > 0 ||
		vdfProof.Cmp(mod) >= 0 {
		return nil, nil, ErrInvalidArgument
	}
	if !v.verifyWesolowski(time, mod) {
		return nil, nil, ErrVerification
	}
	nonce, err := randomInt(random, 16*8)
	if err != nil {
		return nil, nil, err
	}
	randomizedLockedValue := new(big.Int).Exp(lockedValue, nonce, mod)
	return randomizedLockedValue, &TimelockProof{
		VDFTuple: *v,
		Nonce:    newBigUintUnsafe(nonce),
	}, nil
}

var kdfKey = []byte("Tezoskdftimelockv1")

func (p *TimelockProof) SymmetricKey(mod *big.Int) [32]byte {
	if mod == nil {
		mod = rsaModulus
	}
	updated := new(big.Int).Exp(p.VDFTuple.UnlockedValue.Int(), p.Nonce.Int(), mod)
	h, _ := blake2b.New(32, kdfKey)
	h.Write([]byte(updated.String()))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
