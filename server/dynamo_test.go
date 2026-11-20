package server

import (
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr" // nolint
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"

	"github.com/brave-intl/challenge-bypass-server/btd"
	"github.com/brave-intl/challenge-bypass-server/model"
)

func TestLegacyDynamoTable(t *testing.T) {
	t.Setenv("dynamodb_table_legacy", "")
	if got := legacyDynamoTable(); got != "" {
		t.Errorf("empty value: got %q want \"\"", got)
	}

	if err := os.Unsetenv("dynamodb_table_legacy"); err != nil {
		t.Fatal(err)
	}
	if got := legacyDynamoTable(); got != "redemptions" {
		t.Errorf("unset: got %q want \"redemptions\"", got)
	}
}

// fakeDynamo keeps items per table and enforces the attribute_not_exists(id)
// condition that every redemption write uses.
type fakeDynamo struct {
	dynamodbiface.DynamoDBAPI
	tables map[string]map[string]map[string]*dynamodb.AttributeValue
	getErr error
	putErr error
	gets   []*dynamodb.GetItemInput
}

func newFakeDynamo() *fakeDynamo {
	return &fakeDynamo{tables: map[string]map[string]map[string]*dynamodb.AttributeValue{}}
}

func (f *fakeDynamo) GetItem(in *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
	f.gets = append(f.gets, in)
	if f.getErr != nil {
		return nil, f.getErr
	}
	return &dynamodb.GetItemOutput{Item: f.tables[*in.TableName][*in.Key["id"].S]}, nil
}

func (f *fakeDynamo) PutItem(in *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	if f.putErr != nil {
		return nil, f.putErr
	}
	table := f.tables[*in.TableName]
	if table == nil {
		table = map[string]map[string]*dynamodb.AttributeValue{}
		f.tables[*in.TableName] = table
	}
	id := *in.Item["id"].S
	if _, ok := table[id]; ok {
		return nil, awserr.New(dynamodb.ErrCodeConditionalCheckFailedException, "exists", nil)
	}
	table[id] = in.Item
	return &dynamodb.PutItemOutput{}, nil
}

func (f *fakeDynamo) put(t *testing.T, table string, r RedemptionV2) {
	t.Helper()
	_, err := f.PutItem(&dynamodb.PutItemInput{TableName: aws.String(table), Item: mustMarshalMap(t, r)})
	require.NoError(t, err)
}

func (f *fakeDynamo) stored(t *testing.T, table, id string) *RedemptionV2 {
	t.Helper()
	item, ok := f.tables[table][id]
	if !ok {
		return nil
	}
	var r RedemptionV2
	require.NoError(t, dynamodbattribute.UnmarshalMap(item, &r))
	return &r
}

func mustMarshalMap(t *testing.T, r RedemptionV2) map[string]*dynamodb.AttributeValue {
	t.Helper()
	av, err := dynamodbattribute.MarshalMap(r)
	require.NoError(t, err)
	return av
}

func newDynamoServer(f *fakeDynamo) *Server {
	return &Server{Logger: slog.New(slog.DiscardHandler), dynamo: f}
}

// redemptionFixture returns an issuer, a token preimage and the redemption id
// that the issuer and preimage map to.
func redemptionFixture(t *testing.T) (*model.Issuer, *crypto.TokenPreimage, string) {
	t.Helper()
	key, err := crypto.RandomSigningKey()
	require.NoError(t, err)
	token, err := crypto.RandomToken()
	require.NoError(t, err)
	blinded := []*crypto.BlindedToken{token.Blind()}
	signed, proof, err := btd.ApproveTokens(blinded, key)
	require.NoError(t, err)
	unblinded, err := proof.VerifyAndUnblind([]*crypto.Token{token}, blinded, signed, key.PublicKey())
	require.NoError(t, err)
	preimage := unblinded[0].Preimage()
	txt, err := preimage.MarshalText()
	require.NoError(t, err)
	id := uuid.New()
	issuer := &model.Issuer{ID: &id, IssuerType: "test"}
	return issuer, preimage, uuid.NewSHA1(id, txt).String()
}

func TestCheckRedeemedTokenEquivalence(t *testing.T) {
	t.Setenv("dynamodb_table", "redemptions-v2")
	t.Setenv("dynamodb_table_legacy", "redemptions")

	for name, tc := range map[string]struct {
		table   string
		payload string
		want    Equivalence
	}{
		"no record":                                 {"", "", NoEquivalence},
		"the same payload in the write table":       {"redemptions-v2", "binding", BindingEquivalence},
		"another payload in the write table":        {"redemptions-v2", "other", IDEquivalence},
		"the same payload only in the legacy table": {"redemptions", "binding", BindingEquivalence},
		"another payload only in the legacy table":  {"redemptions", "other", IDEquivalence},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeDynamo()
			issuer, preimage, id := redemptionFixture(t)
			if tc.table != "" {
				f.put(t, tc.table, RedemptionV2{IssuerID: issuer.ID.String(), ID: id, Payload: tc.payload})
			}

			got, eq, err := newDynamoServer(f).CheckRedeemedTokenEquivalence(issuer, preimage, "binding", 7)
			require.NoError(t, err)
			assert.Equal(t, tc.want, eq)
			assert.Equal(t, id, got.ID)
			assert.Equal(t, issuer.ID.String(), got.IssuerID)
			assert.Equal(t, "binding", got.Payload)
		})
	}

	t.Run("reads the legacy table consistently and the write table eventually", func(t *testing.T) {
		f := newFakeDynamo()
		issuer, preimage, _ := redemptionFixture(t)
		_, _, err := newDynamoServer(f).CheckRedeemedTokenEquivalence(issuer, preimage, "binding", 0)
		require.NoError(t, err)
		require.Len(t, f.gets, 2)
		assert.Equal(t, "redemptions-v2", *f.gets[0].TableName)
		assert.False(t, *f.gets[0].ConsistentRead)
		assert.Equal(t, "redemptions", *f.gets[1].TableName)
		assert.True(t, *f.gets[1].ConsistentRead)
	})

	t.Run("skips the legacy table when it is turned off", func(t *testing.T) {
		t.Setenv("dynamodb_table_legacy", "")
		f := newFakeDynamo()
		issuer, preimage, id := redemptionFixture(t)
		f.put(t, "redemptions", RedemptionV2{IssuerID: issuer.ID.String(), ID: id, Payload: "binding"})

		_, eq, err := newDynamoServer(f).CheckRedeemedTokenEquivalence(issuer, preimage, "binding", 0)
		require.NoError(t, err)
		assert.Equal(t, NoEquivalence, eq)
		assert.Len(t, f.gets, 1)
	})

	t.Run("sets the TTL from the issuer expiry", func(t *testing.T) {
		issuer, preimage, _ := redemptionFixture(t)
		expiry := time.Date(2030, 8, 19, 0, 0, 0, 0, time.UTC)
		issuer.ExpiresAt = pq.NullTime{Time: expiry, Valid: true}
		got, _, err := newDynamoServer(newFakeDynamo()).CheckRedeemedTokenEquivalence(issuer, preimage, "binding", 0)
		require.NoError(t, err)
		assert.Equal(t, expiry.Unix(), got.TTL)
	})
}

func TestPersistRedemption(t *testing.T) {
	t.Setenv("dynamodb_table", "redemptions-v2")
	r := RedemptionV2{IssuerID: uuid.NewString(), ID: uuid.NewString(), Payload: "binding"}

	t.Run("writes to the write table", func(t *testing.T) {
		f := newFakeDynamo()
		require.NoError(t, newDynamoServer(f).PersistRedemption(r))
		assert.Equal(t, "binding", f.stored(t, "redemptions-v2", r.ID).Payload)
	})

	t.Run("reports a second write of the same id as a duplicate", func(t *testing.T) {
		f := newFakeDynamo()
		s := newDynamoServer(f)
		require.NoError(t, s.PersistRedemption(r))
		assert.ErrorIs(t, s.PersistRedemption(r), ErrDuplicateRedemption)
	})

	t.Run("returns other write failures", func(t *testing.T) {
		f := newFakeDynamo()
		f.putErr = errors.New("connection reset")
		assert.ErrorIs(t, newDynamoServer(f).PersistRedemption(r), f.putErr)
	})
}

func TestRedeemTokenWithDynamo(t *testing.T) {
	t.Setenv("dynamodb_table", "redemptions-v2")
	t.Setenv("dynamodb_table_legacy", "redemptions")

	t.Run("writes the redemption to the write table", func(t *testing.T) {
		f := newFakeDynamo()
		issuer, preimage, id := redemptionFixture(t)
		require.NoError(t, newDynamoServer(f).redeemTokenWithDynamo(issuer, preimage, "binding", 7))
		got := f.stored(t, "redemptions-v2", id)
		require.NotNil(t, got)
		assert.Equal(t, "binding", got.Payload)
		assert.Equal(t, int64(7), got.Offset)
	})

	t.Run("rejects a token redeemed in the write table", func(t *testing.T) {
		f := newFakeDynamo()
		issuer, preimage, _ := redemptionFixture(t)
		s := newDynamoServer(f)
		require.NoError(t, s.redeemTokenWithDynamo(issuer, preimage, "binding", 0))
		assert.ErrorIs(t, s.redeemTokenWithDynamo(issuer, preimage, "binding", 0), ErrDuplicateRedemption)
	})

	t.Run("rejects a token redeemed only in the legacy table", func(t *testing.T) {
		f := newFakeDynamo()
		issuer, preimage, id := redemptionFixture(t)
		f.put(t, "redemptions", RedemptionV2{IssuerID: issuer.ID.String(), ID: id})
		assert.ErrorIs(t, newDynamoServer(f).redeemTokenWithDynamo(issuer, preimage, "binding", 0), ErrDuplicateRedemption)
		assert.Nil(t, f.stored(t, "redemptions-v2", id))
	})

	t.Run("writes the legacy table when no write table is set", func(t *testing.T) {
		t.Setenv("dynamodb_table", "")
		f := newFakeDynamo()
		issuer, preimage, id := redemptionFixture(t)
		require.NoError(t, newDynamoServer(f).redeemTokenWithDynamo(issuer, preimage, "binding", 0))
		assert.NotNil(t, f.stored(t, "redemptions", id))
		assert.Empty(t, f.gets)
	})

	t.Run("returns a legacy lookup failure", func(t *testing.T) {
		f := newFakeDynamo()
		f.getErr = errors.New("connection reset")
		issuer, preimage, _ := redemptionFixture(t)
		assert.ErrorIs(t, newDynamoServer(f).redeemTokenWithDynamo(issuer, preimage, "binding", 0), f.getErr)
	})
}
