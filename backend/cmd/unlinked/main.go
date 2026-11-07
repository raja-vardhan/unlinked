// unlinked runs one role of the demo. Each role is its own process and web
// origin, so the boundaries between wallet, state and sites are real.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"unlinked/internal/console"
	"unlinked/internal/site"
	"unlinked/internal/state"
	"unlinked/internal/trustee"
	"unlinked/internal/web"
)

var ports = map[string]int{
	"wallet":  8080,
	"state":   8081,
	"mirror":  8082,
	"site-a":  8083,
	"site-b":  8084,
	"trustee": 8085,
	"console": 8086,
}

func url(role string) string { return fmt.Sprintf("http://localhost:%d", ports[role]) }

func main() {
	role := flag.String("role", "", "wallet, state, mirror, site-a, site-b, trustee or console")
	dataDir := flag.String("data", "data", "data directory")
	dist := flag.String("dist", "frontend/dist", "built frontend directory")
	flag.Parse()

	port, ok := ports[*role]
	if !ok {
		log.Fatalf("unknown role %q", *role)
	}
	mirrorDir := *dataDir + "/mirror"

	urls := map[string]string{}
	for r := range ports {
		urls[r] = url(r)
	}
	config := map[string]any{"role": *role, "origin": url(*role), "urls": urls}

	mux := http.NewServeMux()
	requests := &web.RequestLog{}

	switch *role {
	case "wallet":
		web.SPA(mux, *dist, config)
	case "state":
		srv, err := state.New(*dataDir+"/state", mirrorDir, url("trustee"), requests)
		if err != nil {
			log.Fatal(err)
		}
		srv.Routes(mux)
	case "mirror":
		mux.Handle("GET /", http.FileServer(http.Dir(mirrorDir)))
	case "trustee":
		srv, err := trustee.New(*dataDir + "/trustee")
		if err != nil {
			log.Fatal(err)
		}
		srv.Routes(mux)
	case "site-a", "site-b":
		cfg := site.Config{
			Role: *role, Origin: url(*role), MirrorURL: url("mirror"), DataDir: *dataDir,
			Title: "Pinecrest Apps", MinAge: 18,
		}
		if *role == "site-b" {
			cfg.Title, cfg.MinAge, cfg.RequireUtah = "Red Rock Cellar", 21, true
		}
		config["site"] = map[string]any{"title": cfg.Title, "minAge": cfg.MinAge, "requireUtah": cfg.RequireUtah}
		site.New(cfg).Routes(mux)
		web.SPA(mux, *dist, config)
	case "console":
		console.New(console.Config{
			SiteAURL: url("site-a"), SiteBURL: url("site-b"), StateURL: url("state"),
		}).Routes(mux)
		web.SPA(mux, *dist, config)
	}

	log.Printf("%s listening on %s", *role, url(*role))
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), web.CORS(requests.Middleware(mux))))
}
