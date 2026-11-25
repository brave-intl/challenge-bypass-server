//go:build act

// Command act-smoke exercises the ACT API end to end against a running cbp,
// playing both the client (credential holder) and the service (origin).
//
//	act-smoke -url http://localhost:2416 [-token $TOKEN] [-issue-token $ISSUE_TOKEN] [-admin-key path] [-issuer name] [-check-sweep 20m]
//
// If the issuer does not exist yet, -admin-key (or $CBP_ADMIN_PRIVATE_KEY) is
// used to sign POST /v1/admin/act/issuers.
//
// -check-sweep also leaves a hold unsettled and waits (up to the given time)
// for the server's sweeper to settle it at cost 0 (after ACT_HOLD_TIMEOUT).
//
// Exits non-zero on the first failed check. See docs/act-credit-tokens.md.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/brave-intl/challenge-bypass-server/act"
	"github.com/brave-intl/challenge-bypass-server/adminapi"
	"github.com/google/uuid"
)

type issuer struct {
	Name      string `json:"name"`
	Params    string `json:"params"`
	Context   string `json:"context"`
	PublicKey []byte `json:"public_key"`
}

type spend struct {
	Nullifier     string     `json:"nullifier"`
	Status        string     `json:"status"`
	Charge        uint64     `json:"charge"`
	Cost          *uint64    `json:"cost"`
	Refund        []byte     `json:"refund"`
	HoldExpiresAt *time.Time `json:"hold_expires_at"`
}

type client struct {
	base       string
	token      string
	issueToken string
	adminKey   ed25519.PrivateKey
	http       *http.Client
}

func (c *client) do(method, path string, body, out any) (int, error) {
	return c.doWithAuth(method, path, c.token, false, body, out)
}

func (c *client) doIssue(path string, body, out any) (int, error) {
	tok := c.issueToken
	if tok == "" {
		tok = c.token
	}
	return c.doWithAuth("POST", path, tok, false, body, out)
}

func (c *client) doAdmin(method, path string, body, out any) (int, error) {
	return c.doWithAuth(method, path, "", true, body, out)
}

func (c *client) doWithAuth(method, path, bearer string, signAdmin bool, body, out any) (int, error) {
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
	if signAdmin {
		if c.adminKey == nil {
			return 0, fmt.Errorf("admin key required for %s %s (pass -admin-key or $CBP_ADMIN_PRIVATE_KEY)", method, path)
		}
		if err := adminapi.SignRequest(req, c.adminKey, time.Now()); err != nil {
			return 0, err
		}
	} else if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("read body: %w", err)
	}
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode %s: %w", raw, err)
		}
	}
	return resp.StatusCode, nil
}

func check(name string, ok bool, detail string, args ...any) {
	status := "PASS"
	if !ok {
		status = "FAIL"
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
	issueToken := flag.String("issue-token", os.Getenv("CBP_ACT_ISSUE_TOKEN"), "ACT issue bearer token (default $CBP_ACT_ISSUE_TOKEN, else first of $ACT_ISSUE_TOKEN_LIST)")
	adminKeyPath := flag.String("admin-key", os.Getenv("CBP_ADMIN_PRIVATE_KEY"), "path to ed25519 operator private key for creating a missing issuer")
	name := flag.String("issuer", "act-smoke-"+time.Now().UTC().Format("2006-01-02"), "issuer to use; created if missing")
	sweepWait := flag.Duration("check-sweep", 0, "also verify the hold sweeper, waiting up to this long (0 = skip)")
	flag.Parse()
	if *token == "" {
		*token = strings.Split(os.Getenv("TOKEN_LIST"), ",")[0]
	}
	if *issueToken == "" {
		*issueToken = strings.Split(os.Getenv("ACT_ISSUE_TOKEN_LIST"), ",")[0]
	}

	var adminKey ed25519.PrivateKey
	if *adminKeyPath != "" {
		var err error
		adminKey, err = adminapi.LoadPrivateKey(*adminKeyPath, func() ([]byte, error) {
			return nil, fmt.Errorf("encrypted admin key not supported in non-interactive smoke test")
		})
		must("load admin key", err)
	}

	c := &client{
		base:       strings.TrimRight(*url, "/"),
		token:      *token,
		issueToken: *issueToken,
		adminKey:   adminKey,
		http:       &http.Client{Timeout: 30 * time.Second},
	}
	base := "/v1/act/issuer/" + *name

	// 1. Issuer
	var iss issuer
	code, err := c.do("GET", base, nil, &iss)
	must("get issuer", err)
	if code == http.StatusNotFound {
		code, err = c.doAdmin("POST", "/v1/admin/act/issuers", map[string]any{
			"name": *name, "max_credits": 1_000_000, "expires_at": time.Now().UTC().Add(48 * time.Hour),
		}, &iss)
		must("create issuer", err)
		check("create issuer", code == http.StatusCreated, "%s -> %d", *name, code)
	} else {
		check("get issuer", code == http.StatusOK, "%s -> %d", *name, code)
	}
	check("issuer params", iss.Params != "" && iss.Context != "" && len(iss.PublicKey) > 0, "params=%s context=%s", iss.Params, iss.Context)

	// 2. Issue 1000 credits
	pre, req, err := act.ClientIssuanceRequest(iss.Params)
	must("issuance request", err)
	var issued struct {
		Response         []byte `json:"response"`
		PurchasedCredits uint64 `json:"purchased_credits"`
		RolledCredits    uint64 `json:"rolled_credits"`
		TotalCredits     uint64 `json:"total_credits"`
	}
	code, err = c.doIssue(base+"/issue", map[string]any{
		"request":         req,
		"credits":         1000,
		"idempotency_key": uuid.NewString(),
	}, &issued)
	must("issue", err)
	check("issue 1000 credits", code == http.StatusOK && issued.TotalCredits == 1000, "-> %d total=%d", code, issued.TotalCredits)
	token0, err := act.ClientFinalizeIssuance(iss.Params, iss.PublicKey, pre, req, issued.Response)
	must("finalize issuance", err)
	bal, err := act.ClientBalance(token0)
	must("credential balance", err)
	check("credential balance", bal == 1000, "balance=%d", bal)

	// 3. Hold 300
	proof, prerefund, err := act.ClientProveSpend(iss.Params, token0, 300)
	must("prove spend", err)
	localNullifier, err := act.ClientSpendNullifier(proof)
	must("client spend nullifier", err)
	idemKey := uuid.NewString()
	var held spend
	start := time.Now()
	code, err = c.do("POST", base+"/spend", map[string]any{"proof": proof, "idempotency_key": idemKey}, &held)
	must("spend", err)
	check("hold 300", code == http.StatusOK && held.Status == "held" && held.Charge == 300 && held.HoldExpiresAt != nil && held.Nullifier == hex.EncodeToString(localNullifier[:]),
		"-> %d status=%s proof=%dB in %s", code, held.Status, len(proof), time.Since(start).Round(time.Millisecond))

	// 4. Idempotent retry, 5. replay with new idempotency key and double spend
	var retry spend
	code, err = c.do("POST", base+"/spend", map[string]any{"proof": proof, "idempotency_key": idemKey}, &retry)
	must("idempotent retry", err)
	check("identical retry is idempotent", code == http.StatusOK && retry.Nullifier == held.Nullifier, "-> %d", code)

	code, err = c.do("POST", base+"/spend", map[string]any{"proof": proof, "idempotency_key": uuid.NewString()}, nil)
	must("replay with different idempotency key", err)
	check("replay with new idempotency_key rejected", code == http.StatusConflict, "-> %d", code)

	proof2, _, err := act.ClientProveSpend(iss.Params, token0, 1)
	must("prove second spend", err)
	code, err = c.do("POST", base+"/spend", map[string]any{"proof": proof2, "idempotency_key": uuid.NewString()}, nil)
	must("double spend", err)
	check("double spend rejected", code == http.StatusConflict, "-> %d", code)

	// 6. Settle at 120
	refundPath := base + "/spend/" + held.Nullifier + "/refund"
	code, err = c.do("POST", refundPath, map[string]any{"cost": 301}, nil)
	must("cost above hold", err)
	check("cost above hold rejected", code == http.StatusBadRequest, "-> %d", code)
	var settled spend
	code, err = c.do("POST", refundPath, map[string]any{"cost": 120}, &settled)
	must("refund", err)
	check("settle at cost 120", code == http.StatusOK && settled.Status == "refunded", "-> %d", code)
	token1, err := act.ClientFinalizeRefund(iss.Params, iss.PublicKey, prerefund, proof, settled.Refund)
	must("finalize refund", err)
	bal, err = act.ClientBalance(token1)
	must("balance after refund", err)
	check("balance after refund", bal == 880, "balance=%d", bal)

	// 7. Recovery by nullifier, conflicting settle
	var got spend
	code, err = c.do("GET", base+"/spend/"+held.Nullifier, nil, &got)
	must("get spend by nullifier", err)
	check("refund recoverable by nullifier", code == http.StatusOK && bytes.Equal(got.Refund, settled.Refund), "-> %d", code)
	code, err = c.do("POST", refundPath, map[string]any{"cost": 100}, nil)
	must("conflicting settle", err)
	check("conflicting settle rejected", code == http.StatusConflict, "-> %d", code)

	// 8. Refunded credential keeps working (cost 0 and full cost == charge)
	proof3, prerefund3, err := act.ClientProveSpend(iss.Params, token1, 880)
	must("prove spend of refunded credential", err)
	var held3 spend
	code, err = c.do("POST", base+"/spend", map[string]any{"proof": proof3, "idempotency_key": uuid.NewString()}, &held3)
	must("spend refunded credential", err)
	check("spend refunded credential", code == http.StatusOK, "-> %d", code)
	var settled3 spend
	code, err = c.do("POST", base+"/spend/"+held3.Nullifier+"/refund", map[string]any{"cost": 0}, &settled3)
	must("settle at cost 0", err)
	check("settle at cost 0", code == http.StatusOK, "-> %d", code)
	token2, err := act.ClientFinalizeRefund(iss.Params, iss.PublicKey, prerefund3, proof3, settled3.Refund)
	must("finalize second refund", err)
	bal, err = act.ClientBalance(token2)
	must("balance preserved", err)
	check("balance preserved", bal == 880, "balance=%d", bal)

	// 9. Settle at full cost (returned = 0)
	proofFull, prerefundFull, err := act.ClientProveSpend(iss.Params, token2, 80)
	must("prove full-cost spend", err)
	var heldFull spend
	code, err = c.do("POST", base+"/spend", map[string]any{"proof": proofFull, "idempotency_key": uuid.NewString()}, &heldFull)
	must("hold 80 for full-cost settle", err)
	check("hold 80 for full-cost settle", code == http.StatusOK, "-> %d", code)
	var settledFull spend
	code, err = c.do("POST", base+"/spend/"+heldFull.Nullifier+"/refund", map[string]any{"cost": 80}, &settledFull)
	must("settle at full cost 80", err)
	check("settle at full cost 80", code == http.StatusOK && settledFull.Status == "refunded", "-> %d", code)
	token3, err := act.ClientFinalizeRefund(iss.Params, iss.PublicKey, prerefundFull, proofFull, settledFull.Refund)
	must("finalize full-cost refund", err)
	bal, err = act.ClientBalance(token3)
	must("balance after full-cost settle", err)
	check("balance after full-cost settle", bal == 800, "balance=%d", bal)

	// 10. Anonymous standalone rollover (same-issuer balance rollover)
	proofRoll, _, err := act.ClientProveSpend(iss.Params, token3, 800)
	must("prove rollover spend", err)
	preRoll, reqRoll, err := act.ClientIssuanceRequest(iss.Params)
	must("rollover issuance request", err)
	var rolled struct {
		Response      []byte `json:"response"`
		RolledCredits uint64 `json:"rolled_credits"`
		TotalCredits  uint64 `json:"total_credits"`
	}
	code, err = c.do("POST", base+"/rollover", map[string]any{
		"request":         reqRoll,
		"idempotency_key": uuid.NewString(),
		"rollover":        []map[string]any{{"proof": proofRoll}},
	}, &rolled)
	must("anonymous rollover", err)
	check("anonymous rollover 800", code == http.StatusOK && rolled.RolledCredits == 800 && rolled.TotalCredits == 800, "-> %d rolled=%d", code, rolled.RolledCredits)
	token3, err = act.ClientFinalizeIssuance(iss.Params, iss.PublicKey, preRoll, reqRoll, rolled.Response)
	must("finalize rolled credential", err)
	bal, err = act.ClientBalance(token3)
	must("balance after rollover", err)
	check("balance preserved after rollover", bal == 800, "balance=%d", bal)

	// 11. Abandoned hold is settled by the sweeper
	if *sweepWait > 0 {
		proof4, prerefund4, err := act.ClientProveSpend(iss.Params, token3, 500)
		must("prove abandoned spend", err)
		var held4 spend
		code, err = c.do("POST", base+"/spend", map[string]any{"proof": proof4, "idempotency_key": uuid.NewString()}, &held4)
		must("hold 500 and abandon it", err)
		check("hold 500 and abandon it", code == http.StatusOK, "-> %d nullifier=%s", code, held4.Nullifier)
		started := time.Now()
		deadline := started.Add(*sweepWait)
		var swept spend
		for time.Now().Before(deadline) {
			if _, err := c.do("GET", base+"/spend/"+held4.Nullifier, nil, &swept); err == nil && swept.Status == "refunded" {
				break
			}
			time.Sleep(10 * time.Second)
		}
		check("sweeper settled abandoned hold", swept.Status == "refunded" && swept.Cost != nil && *swept.Cost == 0,
			"status=%s after %s", swept.Status, time.Since(started).Round(time.Second))
		token4, err := act.ClientFinalizeRefund(iss.Params, iss.PublicKey, prerefund4, proof4, swept.Refund)
		must("finalize swept refund", err)
		bal, err = act.ClientBalance(token4)
		must("full balance returned", err)
		check("full balance returned", bal == 800, "balance=%d", bal)
	}

	fmt.Println("OK: all ACT checks passed against", c.base)
}
