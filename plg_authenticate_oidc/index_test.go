package plg_authenticate_oidc

import (
	"os"
	"slices"
	"testing"

	. "github.com/mickael-kerjean/filestash/server/common"
	"github.com/mickael-kerjean/filestash/server/pkg/config"
	"github.com/mickael-kerjean/filestash/server/pkg/env"
)

func TestMain(m *testing.M) {
	config.InitSecretDerivate("0123456789abcdef")
	os.Exit(m.Run())
}

type payload struct {
	Groups []string `json:"groups"`
}

func TestSealRoundTrip(t *testing.T) {
	s, err := seal("A", payload{Groups: []string{"team-1", "team-2"}})
	if err != nil {
		t.Fatal(err)
	}
	var p payload
	if err := unseal("A", s, &p); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.Groups, []string{"team-1", "team-2"}) {
		t.Fatalf("got %v", p.Groups)
	}
}

func TestUnsealRejectsTampering(t *testing.T) {
	s, _ := seal("A", payload{Groups: []string{"team-1"}})
	c := byte('A')
	if s[10] == c {
		c = 'B'
	}
	var p payload
	if err := unseal("A", s[:10]+string(c)+s[11:], &p); err == nil {
		t.Fatal("tampered value accepted")
	}
}

func TestUnsealRejectsOtherPurpose(t *testing.T) {
	s, _ := seal("A", payload{Groups: []string{"team-1"}})
	var p payload
	if err := unseal("B", s, &p); err == nil {
		t.Fatal("value sealed for another purpose accepted")
	}
}

func TestUnsealRejectsFilestashSession(t *testing.T) {
	s, err := EncryptString(env.SECRET_KEY_DERIVATE_FOR_USER, `{"groups":["team-1"]}`)
	if err != nil {
		t.Fatal(err)
	}
	var p payload
	if err := unseal("A", s, &p); err == nil {
		t.Fatal("session token accepted")
	}
}

func TestUnsealRejectsGarbage(t *testing.T) {
	for _, s := range []string{"", "garbage", "Zm9v"} {
		var p payload
		if err := unseal("A", s, &p); err == nil {
			t.Fatalf("%q accepted", s)
		}
	}
}
