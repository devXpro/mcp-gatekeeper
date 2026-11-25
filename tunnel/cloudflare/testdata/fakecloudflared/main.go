// Command fakecloudflared plays the cloudflared CLI for the tests of package cloudflare. The tests build it, copy it
// next to a "control" directory and steer it with files in there; it never talks to the network except its own
// loopback metrics server.
//
//	cloudflared tunnel login          prints the authorization link, then waits for control/login-release (or fails at
//	                                  once with control/login-fail) and writes the certificate to $TUNNEL_ORIGIN_CERT
//	                                  (not with control/no-cert)
//	cloudflared tunnel create ...     writes the credentials file (fails with control/create-fail)
//	cloudflared tunnel route dns ...  succeeds (with control/dns-exists it refuses like an existing record, unless
//	                                  --overwrite-dns is given)
//	cloudflared tunnel ... run        a named tunnel: appends its arguments and environment to control/runs.jsonl,
//	                                  prints "Registered tunnel connection" and stays up
//	cloudflared tunnel ... --url U    a quick tunnel: the same, serves GET /quicktunnel on --metrics with the hostname
//	                                  example-<run number>.trycloudflare.com (a new one at every start) and prints it
//
// A running tunnel exits with status 1 when control/die appears (the file is removed first, so the next start stays
// up), or at once when control/exit-now exists. control/no-metrics keeps the metrics server off (a test can then
// serve the --metrics port itself, as another program that took it) and control/no-log-url keeps the hostname out of
// the log (the supervisor must then never publish the one the metrics server names); control/no-register holds back
// "Registered tunnel connection".
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const tunnelID = "6ff42ae2-765d-4adf-8112-31c55c1551ef"

var ctl string

func has(name string) bool {
	_, err := os.Stat(filepath.Join(ctl, name))
	return err == nil
}

func die(code int, format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(code)
}

func main() {
	exe, err := os.Executable()
	if err != nil {
		die(2, "%v", err)
	}
	ctl = filepath.Join(filepath.Dir(exe), "control")
	args := os.Args[1:]
	if len(args) == 0 || args[0] != "tunnel" {
		die(2, "unexpected arguments %v", args)
	}
	rest := args[1:]
	if len(rest) > 0 {
		switch rest[0] {
		case "login":
			login()
			return
		case "create":
			create(rest)
			return
		case "route":
			if has("dns-exists") && !contains(rest, "--overwrite-dns") {
				fmt.Println("Failed to add route: code: 1003, reason: An A, AAAA, or CNAME record with that host already exists.")
				os.Exit(1)
			}
			fmt.Printf("Added CNAME %s which will route to this tunnel\n", rest[len(rest)-1])
			return
		}
	}
	run(rest)
}

func login() {
	fmt.Println("Please open the following URL and log in with your Cloudflare account:")
	fmt.Println()
	fmt.Println("https://dash.cloudflare.com/argotunnel?aud=&callback=https%3A%2F%2Flogin.cloudflareaccess.org%2Fabc")
	fmt.Println()
	fmt.Println("Leave cloudflared running to download the cert automatically.")
	if has("login-fail") {
		die(1, "Failed to fetch resource")
	}
	for deadline := time.Now().Add(30 * time.Second); !has("login-release"); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			die(1, "timed out waiting for the test")
		}
	}
	if has("no-cert") {
		return
	}
	cert := os.Getenv("TUNNEL_ORIGIN_CERT")
	if err := os.MkdirAll(filepath.Dir(cert), 0o700); err != nil {
		die(1, "%v", err)
	}
	if err := os.WriteFile(cert, []byte("CERT"), 0o600); err != nil {
		die(1, "%v", err)
	}
	fmt.Println("You have successfully logged in.")
}

func create(args []string) {
	if has("create-fail") {
		die(1, "failed to create tunnel: boom")
	}
	var creds, name string
	for i, a := range args {
		if a == "--credentials-file" && i+1 < len(args) {
			creds = args[i+1]
			name = args[len(args)-1]
		}
	}
	if creds == "" {
		die(2, "no --credentials-file in %v", args)
	}
	body := `{"AccountTag":"acc","TunnelSecret":"c2VjcmV0","TunnelID":"` + tunnelID + `"}`
	if err := os.WriteFile(creds, []byte(body), 0o644); err != nil { //nolint:gosec // the fake writes what cloudflared writes
		die(1, "%v", err)
	}
	fmt.Printf("Created tunnel %s with id %s\n", name, tunnelID)
}

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// flag returns the value after name in args.
func flag(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func run(args []string) {
	n := record(os.Args[1:])
	if has("exit-now") {
		die(1, "boom: the fake was told to exit at once")
	}
	quick := flag(args, "--url") != ""
	host := fmt.Sprintf("example-%d.trycloudflare.com", n)
	if quick {
		fmt.Println("INF Requesting new quick Tunnel on trycloudflare.com...")
		fmt.Println("INF Posting to https://api.trycloudflare.com/tunnel")
		if !has("no-log-url") {
			fmt.Println("INF +--------------------------------------------------------------------------------------------+")
			fmt.Println("INF |  Your quick Tunnel has been created! Visit it at (it may take some time to be reachable):  |")
			fmt.Printf("INF |  https://%-82s|\n", host)
			fmt.Println("INF +--------------------------------------------------------------------------------------------+")
		}
		if !has("no-metrics") {
			l, err := net.Listen("tcp", flag(args, "--metrics"))
			if err != nil {
				die(1, "metrics: %v", err)
			}
			mux := http.NewServeMux()
			mux.HandleFunc("/quicktunnel", func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]string{"hostname": host})
			})
			go func() { _ = http.Serve(l, mux) }() //nolint:gosec // a test fake on loopback
		}
	} else if !has("no-register") {
		fmt.Println("INF Registered tunnel connection connIndex=0 connection=00000000-0000-0000-0000-000000000000 event=0 ip=198.51.100.1 location=xxx protocol=quic")
	}
	for !has("die") {
		time.Sleep(10 * time.Millisecond)
	}
	_ = os.Remove(filepath.Join(ctl, "die"))
	die(1, "ERR Connection terminated error=\"the test killed it\"")
}

// record appends this run (arguments, environment, how many entries HOME holds) to control/runs.jsonl and returns its
// number, counting from 1.
func record(args []string) int {
	path := filepath.Join(ctl, "runs.jsonl")
	b, _ := os.ReadFile(path) //nolint:gosec // the test's own file
	n := strings.Count(string(b), "\n") + 1
	home, _ := os.ReadDir(os.Getenv("HOME"))
	line, err := json.Marshal(map[string]any{"n": n, "args": args, "env": os.Environ(), "homeEntries": len(home), "pid": os.Getpid()})
	if err != nil {
		die(2, "%v", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // the test's own file
	if err != nil {
		die(2, "%v", err)
	}
	_, _ = f.Write(append(line, '\n'))
	_ = f.Close()
	return n
}
