package pat

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/group"
)

func TestDLEQ(t *testing.T) {

	x := group.Ristretto255.RandomScalar(rand.Reader)
	r := group.Ristretto255.RandomScalar(rand.Reader)

	g := group.Ristretto255.Generator()
	h := group.Ristretto255.HashToElement([]byte("second generator"), []byte("generator DST"))

	gx := group.Ristretto255.NewElement()
	gx.MulGen(x)

	hr := group.Ristretto255.NewElement()
	hr.Mul(h, r)

	c := group.Ristretto255.NewElement()
	c.Add(gx, hr)

	A := []group.Element{gx, c}
	B := [][]group.Element{
		{g, nil},
		{g, h},
	}
	B2 := [][]group.Element{
		{g, h},
		{h, g},
	}
	svec := []group.Scalar{x, r}
	err := VerifyProofParams(A, B, svec, group.Ristretto255)
	if err != nil {
		t.Error(err)
	}
	err = VerifyProofParams(A, B2, svec, group.Ristretto255)
	if err == nil {
		t.Errorf("Incorrect parameters should not verify")
	}

	p, err := ComputeProof(A, B, svec, group.Ristretto255, []byte("DLEQ test proof"))
	if err != nil {
		t.Error(err)
		return
	}

	encodedProof, err := p.MarshalCompact()
	if err != nil {
		t.Error(err)
		return
	}

	decodedProof, err := UnmarshalProofCompact(encodedProof, group.Ristretto255)
	if err != nil {
		t.Error(err)
		return
	}

	result, err := VerifyProofCompact(decodedProof, A, B, group.Ristretto255, []byte("DLEQ test proof"))
	if !result {
		t.Errorf("Proof verification failed: %s", err)
	}
}
