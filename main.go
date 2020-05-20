package main

import (
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/kaancfidan/jwt-bouncer/bouncer"
)

func main() {
	upstreamUrl,err := url.Parse(os.Getenv("BOUNCER_UPSTREAM_URL"))

	if err != nil{
		log.Fatalf("upstream url could not be parsed: %v", err)
	}

	b := bouncer.New(upstreamUrl)

	// TODO parse config

	http.HandleFunc("/", b.Proxy)

	err = http.ListenAndServe(":3512", nil)

	log.Fatal(err)
}
