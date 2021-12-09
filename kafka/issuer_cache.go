package kafka

import (
	"errors"
	"fmt"
	cbpServer "github.com/brave-intl/challenge-bypass-server/server"
	"time"
)

// initIssuersGetter takes a a serverIssueFetcher which is shared with the API through the
// server object (@TODO: break this functionality out of the API) and returns a function
// that will conditionally call that serverIssueFetcher function or return out of local
// cache depending on how long it has been since the last fetch of issuers. The local cache
// for this implementation is a simple closure over local variables.
func initIssuersGetter(serverIssueFetcher func() (*[]cbpServer.Issuer, error)) func(string) (*[]cbpServer.Issuer, error) {
	var (
		issuers             *[]cbpServer.Issuer
		lastIssuerFetchDate time.Time
		issueFetcher        func() (*[]cbpServer.Issuer, error)
	)

	loc, _ := time.LoadLocation("UTC")
	issueFetcher = serverIssueFetcher
	return func(requestId string) (*[]cbpServer.Issuer, error) {
		if lastIssuerFetchDate.Before(time.Now().In(loc).Add(1 * time.Hour)) {
			latestIssuers, err := issueFetcher()
			if err != nil {
				return nil, errors.New(
					fmt.Sprintf(
						"Request %s: Failed to fetch all issuers with error %e",
						requestId,
						err,
					),
				)
			}
			issuers = latestIssuers
		}
		return issuers, nil
	}
}
