// verify checks a saved proof using only local files. It opens no sockets, so it
// runs inside an empty network namespace: `unshare -rn bin/verify ...`.
// Supports the offline requirement in 63A-20-301(1)(d) and the no-monitoring
// requirement in 63A-20-301(3).
package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"unlinked/internal/core"
)

func main() {
	proofPath := flag.String("proof", "data/site-a/last-presentation.json", "saved presentation")
	mirror := flag.String("mirror", "data/mirror", "local copy of the public mirror")
	origin := flag.String("origin", "http://localhost:8083", "origin of the site that requested the proof")
	flag.Parse()

	fmt.Println("Offline verification")
	reportNetwork()

	var p core.Presentation
	must(read(*proofPath, &p))
	var issuer core.IssuerKey
	must(read(*mirror+"/issuer.json", &issuer))
	var snap core.Snapshot
	must(read(*mirror+"/revocation.json", &snap))
	must(snap.Verify(issuer))
	fmt.Printf("  revocation list    epoch %d, %d entries, issuer signature valid\n", snap.Epoch, len(snap.Revoked))

	vkey, err := os.ReadFile(*mirror + "/verification_key.json")
	must(err)

	err = core.Check(p, vkey, core.Expected{
		Issuer:  issuer,
		Scope:   core.ScopeOf(*origin).String(),
		RevRoot: snap.Root,
	})
	if err != nil {
		fmt.Printf("  result             REJECTED: %v\n", err)
		os.Exit(1)
	}

	named, err := p.Named()
	must(err)
	fmt.Printf("  age question       born on or before %s\n", named["cutoffDate"])
	fmt.Printf("  residency required %s\n", named["requireUtah"])
	fmt.Println("  result             VALID")
	fmt.Println("  not checked here   nonce freshness and proof date, which belong to the live site")
}

func reportNetwork() {
	addrs, err := net.Interfaces()
	if err != nil {
		fmt.Printf("  network            unavailable (%v)\n", err)
		return
	}
	up := 0
	for _, i := range addrs {
		if i.Flags&net.FlagUp != 0 {
			up++
		}
	}
	fmt.Printf("  network interfaces %d up\n", up)
}

func read(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return core.LoadJSON(raw, v)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}
