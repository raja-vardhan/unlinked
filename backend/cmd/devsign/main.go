// devsign exposes the Go cryptography to the circuit tests, so they exercise the
// same code paths the issuer and verifiers use. It is test tooling and uses a
// fixed key that is never used by the running services.
package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/iden3/go-iden3-crypto/babyjub"

	"unlinked/internal/core"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: devsign sign|poseidon|smt|scope|verify ...")
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "sign":
		var key babyjub.PrivateKey
		copy(key[:], "unlinked-test-key-do-not-deploy!")
		msg := parse(args[0])
		sig := key.SignPoseidon(msg)
		pub := key.Public()
		out(map[string]string{
			"ax": pub.X.String(), "ay": pub.Y.String(),
			"r8x": sig.R8.X.String(), "r8y": sig.R8.Y.String(), "s": sig.S.String(),
		})
	case "poseidon":
		fmt.Println(core.Poseidon(parseAll(args)...).String())
	case "smt":
		root, err := core.RevocationRoot(parseAll(args))
		check(err)
		fmt.Println(root.String())
	case "scope":
		fmt.Println(core.ScopeOf(args[0]).String())
	case "verify":
		// Pure proof check: no policy values, so only the Groth16 equation runs.
		raw, err := os.ReadFile(args[0])
		check(err)
		var p core.Presentation
		check(core.LoadJSON(raw, &p))
		vkey, err := os.ReadFile(args[1])
		check(err)
		check(core.Check(p, vkey, core.Expected{}))
		fmt.Println("valid")
	default:
		fail("unknown command")
	}
}

func parse(s string) *big.Int {
	n, err := core.ParseField(s)
	check(err)
	return n
}

func parseAll(ss []string) []*big.Int {
	out := make([]*big.Int, len(ss))
	for i, s := range ss {
		out[i] = parse(s)
	}
	return out
}

func out(v any) {
	b, err := json.Marshal(v)
	check(err)
	fmt.Println(string(b))
}

func check(err error) {
	if err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
