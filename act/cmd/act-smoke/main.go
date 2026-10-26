//go:build act

// Command act-smoke exercises the ACT API end to end against a running cbp,
// playing both the client (credential holder) and the service (origin).
//
//	act-smoke -url http://localhost:2416 [-token $TOKEN] [-issuer name] [-check-sweep 20m]
//
// -check-sweep also leaves a hold unsettled and waits (up to the given time)
// for the server's sweeper to settle it at cost 0 (after ACT_HOLD_TIMEOUT).
//
// Exits non-zero on the first failed check. See docs/act-credit-tokens.md.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/brave-intl/challenge-bypass-server/act"
)

type issuer struct {
	Name      string `json:"name"`
	Params    string `json:"params"`
	PublicKey []byte `json:"public_key"`
}

type spend struct {
	Nullifier string  `json:"nullifier"`
	Status    string  `json:"status"`
	Charge    uint64  `json:"charge"`
	Cost      *uint64 `json:"cost"`
	Refund    []byte  `json:"refund"`
}

type client struct {
	base  string
	token string
	http  *http.Client
}

func (c *client) do(method, path string, body, out any) (int, error) {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return 0, err
		}
	}
	req, err := http.NewRequest(method, c.base+path, &buf)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode %s: %w", raw, err)
		}
	}
	return resp.StatusCode, nil
}

var failed bool

func check(name string, ok bool, detail string, args ...any) {
	status := "PASS"
	if !ok {
		status, failed = "FAIL", true
	}
	fmt.Printf("%s  %-44s %s\n", status, name, fmt.Sprintf(detail, args...))
	if !ok {
		os.Exit(1)
	}
}

func must(name string, err error) {
	if err != nil {
		check(name, false, "%v", err)
	}
}

func main() {
	url := flag.String("url", "http://localhost:2416", "cbp base URL")
	token := flag.String("token", os.Getenv("CBP_TOKEN"), "bearer token (default $CBP_TOKEN, else first of $TOKEN_LIST)")
	name := flag.String("issuer", "act-smoke-"+time.Now().UTC().Format("2006-01-02"), "issuer to use; created if missing")
	sweepWait := flag.Duration("check-sweep", 0, "also verify the hold sweeper, waiting up to this long (0 = skip)")
	flag.Parse()
	if *token == "" {
		*token = strings.Split(os.Getenv("TOKEN_LIST"), ",")[0]
	}

	c := &client{base: strings.TrimRight(*url, "/"), token: *token, http: &http.Client{Timeout: 30 * time.Second}}
	base := "/v1/act/issuer/" + *name

	// 1. Issuer
	var iss issuer
	code, err := c.do("GET", base, nil, &iss)
	must("get issuer", err)
	if code == http.StatusNotFound {
		code, err = c.do("POST", "/v1/act/issuer", map[string]any{
			"name": *name, "max_credits": 1_000_000, "expires_at": time.Now().Add(48 * time.Hour),
		}, &iss)
		must("create issuer", err)
		check("create issuer", code == http.StatusCreated, "%s -> %d", *name, code)
	} else {
		check("get issuer", code == http.StatusOK, "%s -> %d", *name, code)
	}
	check("issuer params", iss.Params != "" && len(iss.PublicKey) > 0, "params=%s", iss.Params)

	// 2. Issue 1000 credits
	pre, req, err := act.ClientIssuanceRequest(iss.Params)
	must("issuance request", err)
	var issued struct {
		Response []byte `json:"response"`
	}
	code, err = c.do("POST", base+"/issue", map[string]any{"request": req, "credits": 1000}, &issued)
	must("issue", err)
	check("issue 1000 credits", code == http.StatusOK, "-> %d", code)
	token0, err := act.ClientFinalizeIssuance(iss.Params, iss.PublicKey, pre, req, issued.Response)
	must("finalize issuance", err)
	bal, _ := act.ClientBalance(token0)
	check("credential balance", bal == 1000, "balance=%d", bal)

	// 3. Hold 300
	proof, prerefund, err := act.ClientProveSpend(iss.Params, token0, 300)
	must("prove spend", err)
	var held spend
	start := time.Now()
	code, err = c.do("POST", base+"/spend", map[string]any{"proof": proof}, &held)
	must("spend", err)
	check("hold 300", code == http.StatusOK && held.Status == "held" && held.Charge == 300,
		"-> %d status=%s proof=%dB in %s", code, held.Status, len(proof), time.Since(start).Round(time.Millisecond))

	// 4. Idempotent retry, 5. double spend
	var retry spend
	code, _ = c.do("POST", base+"/spend", map[string]any{"proof": proof}, &retry)
	check("identical retry is idempotent", code == http.StatusOK && retry.Nullifier == held.Nullifier, "-> %d", code)
	proof2, _, err := act.ClientProveSpend(iss.Params, token0, 1)
	must("prove second spend", err)
	code, _ = c.do("POST", base+"/spend", map[string]any{"proof": proof2}, nil)
	check("double spend rejected", code == http.StatusConflict, "-> %d", code)

	// 6. Settle at 120
	refundPath := base + "/spend/" + held.Nullifier + "/refund"
	code, _ = c.do("POST", refundPath, map[string]any{"cost": 301}, nil)
	check("cost above hold rejected", code == http.StatusBadRequest, "-> %d", code)
	var settled spend
	code, err = c.do("POST", refundPath, map[string]any{"cost": 120}, &settled)
	must("refund", err)
	check("settle at cost 120", code == http.StatusOK && settled.Status == "refunded", "-> %d", code)
	token1, err := act.ClientFinalizeRefund(iss.Params, iss.PublicKey, prerefund, proof, settled.Refund)
	must("finalize refund", err)
	bal, _ = act.ClientBalance(token1)
	check("balance after refund", bal == 880, "balance=%d", bal)

	// 7. Recovery by nullifier, conflicting settle
	var got spend
	code, _ = c.do("GET", base+"/spend/"+held.Nullifier, nil, &got)
	check("refund recoverable by nullifier", code == http.StatusOK && bytes.Equal(got.Refund, settled.Refund), "-> %d", code)
	code, _ = c.do("POST", refundPath, map[string]any{"cost": 100}, nil)
	check("conflicting settle rejected", code == http.StatusConflict, "-> %d", code)

	// 8. Refunded credential keeps working
	proof3, prerefund3, err := act.ClientProveSpend(iss.Params, token1, 880)
	must("prove spend of refunded credential", err)
	var held3 spend
	code, _ = c.do("POST", base+"/spend", map[string]any{"proof": proof3}, &held3)
	check("spend refunded credential", code == http.StatusOK, "-> %d", code)
	var settled3 spend
	code, _ = c.do("POST", base+"/spend/"+held3.Nullifier+"/refund", map[string]any{"cost": 0}, &settled3)
	check("settle at cost 0", code == http.StatusOK, "-> %d", code)
	token2, err := act.ClientFinalizeRefund(iss.Params, iss.PublicKey, prerefund3, proof3, settled3.Refund)
	must("finalize second refund", err)
	bal, _ = act.ClientBalance(token2)
	check("balance preserved", bal == 880, "balance=%d", bal)

	// 9. Abandoned hold is settled by the sweeper
	if *sweepWait > 0 {
		proof4, prerefund4, err := act.ClientProveSpend(iss.Params, token2, 500)
		must("prove abandoned spend", err)
		var held4 spend
		code, _ = c.do("POST", base+"/spend", map[string]any{"proof": proof4}, &held4)
		check("hold 500 and abandon it", code == http.StatusOK, "-> %d nullifier=%s", code, held4.Nullifier)
		deadline := time.Now().Add(*sweepWait)
		var swept spend
		for time.Now().Before(deadline) {
			if c.do("GET", base+"/spend/"+held4.Nullifier, nil, &swept); swept.Status == "refunded" {
				break
			}
			time.Sleep(10 * time.Second)
		}
		check("sweeper settled abandoned hold", swept.Status == "refunded" && swept.Cost != nil && *swept.Cost == 0,
			"status=%s after %s", swept.Status, time.Since(deadline.Add(-*sweepWait)).Round(time.Second))
		token3, err := act.ClientFinalizeRefund(iss.Params, iss.PublicKey, prerefund4, proof4, swept.Refund)
		must("finalize swept refund", err)
		bal, _ = act.ClientBalance(token3)
		check("full balance returned", bal == 880, "balance=%d", bal)
	}

	if !failed {
		fmt.Println("OK: all ACT checks passed against", c.base)
	}
}
