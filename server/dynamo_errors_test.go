package server

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws/awserr" // nolint
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/brave-intl/challenge-bypass-server/utils"
)

// A temporary error makes the kafka consumer retry the message. A permanent
// one makes it emit an error result, which pays nothing.
func TestCheckRedeemedTokenEquivalenceTemporaryErrors(t *testing.T) {
	t.Setenv("dynamodb_table", "redemptions-v2")
	for err, want := range map[error]bool{
		awserr.New(dynamodb.ErrCodeProvisionedThroughputExceededException, "", nil): true,
		awserr.New(dynamodb.ErrCodeRequestLimitExceeded, "", nil):                   true,
		awserr.New(dynamodb.ErrCodeInternalServerError, "", nil):                    true,
		awserr.New(dynamodb.ErrCodeResourceNotFoundException, "", nil):              false,
		errors.New("not an aws error"):                                              false,
	} {
		f := newFakeDynamo()
		f.getErr = err
		issuer, preimage, _ := redemptionFixture(t)
		_, _, got := newDynamoServer(f).CheckRedeemedTokenEquivalence(issuer, preimage, "binding", 0)
		var pe *utils.ProcessingError
		require.ErrorAs(t, got, &pe)
		assert.ErrorIs(t, got, err)
		assert.Equal(t, want, pe.Temporary, err.Error())
	}
}
