package cryptutil_test

import (
	"crypto/rand"
	"log"
	"testing"

	"github.com/KarpelesLab/cryptutil"
)

func TestBottle(t *testing.T) {
	bottle := cryptutil.NewBottle([]byte("hello world!"))

	// encrypt for bob
	bottle.Encrypt(rand.Reader, bob.Public())
	bottle.BottleUp()
	bottle.Sign(rand.Reader, alice) // from Alice

	opener := must(cryptutil.NewOpener(bob))
	res, info, err := opener.Open(bottle)
	if err != nil {
		t.Errorf("failed to open bottle: %s", err)
	}
	if info.Decryption != 1 {
		t.Errorf("expected 1 decrypt")
	}
	if string(res) != "hello world!" {
		t.Errorf("bad decrypt result in bottle")
	}
	if !info.SignedBy(alice.Public()) {
		t.Errorf("message does not appear as signed by Alice")
	}
	if info.SignedBy(bob.Public()) {
		t.Errorf("message appears signed by Bob but shouldn't")
	}

	log.Printf("bottle open res = %+v", info)
}
