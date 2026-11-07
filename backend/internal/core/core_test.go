package core

import (
	"math/big"
	"testing"
	"time"

	"github.com/iden3/go-iden3-crypto/babyjub"
)

func TestCutoffIsCalendarExact(t *testing.T) {
	cases := []struct {
		name          string
		today, minAge int
		dob           int
		want          bool
	}{
		{"18 today", 20261106, 18, 20081106, true},
		{"one day short of 18", 20261106, 18, 20081107, false},
		{"leap-day birth, day before birthday", 20260228, 18, 20080229, false},
		{"leap-day birth, day after", 20260301, 18, 20080229, true},
		{"21 today", 20261106, 21, 20051106, true},
	}
	for _, c := range cases {
		if got := c.dob <= Cutoff(c.today, c.minAge); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestValidDate(t *testing.T) {
	for d, want := range map[int]bool{
		19900101: true, 20240229: true, 20230229: false, 19901301: false, 19900132: false, 123: false,
	} {
		if got := ValidDate(d); got != want {
			t.Errorf("ValidDate(%d) = %v, want %v", d, got, want)
		}
	}
}

func TestDateIntUsesUTC(t *testing.T) {
	loc := time.FixedZone("behind", -7*3600)
	if got := DateInt(time.Date(2026, 11, 6, 22, 0, 0, 0, loc)); got != 20261107 {
		t.Errorf("got %d, want 20261107", got)
	}
}

func TestRevocationRootIgnoresOrder(t *testing.T) {
	keys := []*big.Int{big.NewInt(1), big.NewInt(3), big.NewInt(5), big.NewInt(7), big.NewInt(1024)}
	reversed := []*big.Int{keys[4], keys[3], keys[2], keys[1], keys[0]}
	a, err := RevocationRoot(keys)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RevocationRoot(reversed)
	if err != nil {
		t.Fatal(err)
	}
	if a.Cmp(b) != 0 {
		t.Error("root depends on order")
	}
}

func TestSnapshotRejectsTampering(t *testing.T) {
	key := babyjub.NewRandPrivKey()
	pub := key.Public()
	issuer := IssuerKey{Ax: pub.X.String(), Ay: pub.Y.String()}
	handle := big.NewInt(99)
	root, err := RevocationRoot([]*big.Int{handle})
	if err != nil {
		t.Fatal(err)
	}
	snap := Snapshot{
		Epoch:   2,
		Revoked: []string{handle.String()},
		Root:    root.String(),
		Sig:     SigFrom(key.SignPoseidon(SnapshotMessage(root, 2))),
	}
	if err := snap.Verify(issuer); err != nil {
		t.Fatalf("valid snapshot rejected: %v", err)
	}

	// A mirror that drops a revoked entry must be caught.
	dropped := snap
	dropped.Revoked = nil
	if dropped.Verify(issuer) == nil {
		t.Error("accepted a snapshot with an entry removed")
	}

	// A mirror that serves an empty list with an empty root must be caught too.
	emptied := dropped
	emptied.Root = "0"
	if emptied.Verify(issuer) == nil {
		t.Error("accepted an unsigned empty list")
	}

	// A mirror that replays an older epoch number must be caught.
	replayed := snap
	replayed.Epoch = 1
	if replayed.Verify(issuer) == nil {
		t.Error("accepted a changed epoch")
	}
}

func TestScopeFitsInField(t *testing.T) {
	if _, err := ParseField(ScopeOf("https://example.test").String()); err != nil {
		t.Error(err)
	}
}
