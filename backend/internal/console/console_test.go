package console

import (
	"fmt"
	"testing"

	"unlinked/internal/site"
)

func zkEntry(i int, name string) site.Entry {
	return site.Entry{Fields: map[string]string{
		"issuerAx": "issuer", "today": "20261106", "revRoot": "0", "cutoffDate": "cutoff-" + name, "scope": "scope-" + name,
		"nonce": fmt.Sprintf("nonce-%s-%d", name, i), "proof.a[0]": fmt.Sprintf("proof-%s-%d", name, i),
	}}
}

func stdEntry(i int) site.Entry {
	return site.Entry{Fields: map[string]string{
		"claim.ageOver18": "1", "signature.s": fmt.Sprintf("sig-%d", i), "leaf[0]": fmt.Sprintf("leaf-%d", i),
	}}
}

func crowd(n int, entry func(int) site.Entry) []site.Entry {
	out := make([]site.Entry, n)
	for i := range out {
		out[i] = entry(i)
	}
	return out
}

func TestStandardCredentialLinksEveryone(t *testing.T) {
	a := crowd(10, stdEntry)
	b := crowd(10, stdEntry)
	res := Attack("standard", "A", "B", a, b, nil, false)
	if res.LinkedA != 10 {
		t.Errorf("linked %d of 10", res.LinkedA)
	}
}

func TestZKProofsDoNotLink(t *testing.T) {
	a := crowd(10, func(i int) site.Entry { return zkEntry(i, "a") })
	b := crowd(10, func(i int) site.Entry { return zkEntry(i, "b") })
	res := Attack("zk", "A", "B", a, b, nil, false)
	if res.LinkedA != 0 || len(res.Links) != 0 {
		t.Errorf("expected no links, got %d: %+v", res.LinkedA, res.Links)
	}
}

func TestCheatingStateNamesStandardHoldersOnly(t *testing.T) {
	shadow := []shadowRecord{{Person: "Target", Values: map[string]string{"signature.s": "sig-3", "credentialHash": "secret-hash"}}}

	std := Attack("standard", "A", "B", crowd(5, stdEntry), crowd(5, stdEntry), shadow, true)
	if len(std.Identified) != 2 || std.Identified[0].Person != "Target" {
		t.Errorf("standard: expected Target named on both sites, got %+v", std.Identified)
	}

	a := crowd(5, func(i int) site.Entry { return zkEntry(i, "a") })
	b := crowd(5, func(i int) site.Entry { return zkEntry(i, "b") })
	zk := Attack("zk", "A", "B", a, b, shadow, true)
	if len(zk.Identified) != 0 {
		t.Errorf("zk: expected nobody named, got %+v", zk.Identified)
	}
}

// If the attack cannot spot a planted identifier, a "0 links" result means nothing.
func TestAttackDetectsPlantedIdentifierInZKMode(t *testing.T) {
	a := crowd(10, func(i int) site.Entry { return zkEntry(i, "a") })
	b := crowd(10, func(i int) site.Entry { return zkEntry(i, "b") })
	a[4].Fields["nullifier"] = "same-person"
	b[7].Fields["nullifier"] = "same-person"
	res := Attack("zk", "A", "B", a, b, nil, false)
	if res.LinkedA != 1 || res.Links[0].SiteA != 4 || res.Links[0].SiteB != 7 {
		t.Errorf("planted link not found: %+v", res.Links)
	}
}

func TestWindowFieldsNeverCountAsLinks(t *testing.T) {
	a := crowd(10, func(i int) site.Entry { return zkEntry(i, "a") })
	b := crowd(10, func(i int) site.Entry { return zkEntry(i, "b") })
	// One holder presents to both sites right after a new revocation epoch.
	a[0].Fields["revRoot"] = "new-epoch"
	b[0].Fields["revRoot"] = "new-epoch"
	res := Attack("zk", "A", "B", a, b, nil, false)
	if res.LinkedA != 0 {
		t.Errorf("window field treated as a personal link: %+v", res.Links)
	}
}
