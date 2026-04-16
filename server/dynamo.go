package server

import (
	"errors"
	"os"
	"time"

	"github.com/brave-intl/challenge-bypass-server/model"

	awsDynamoTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr" // nolint
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	"github.com/brave-intl/challenge-bypass-server/utils"
	"github.com/google/uuid"
)

// Equivalence represents the type of equality discovered when checking DynamoDB data
type Equivalence int64

const (
	// UnknownEquivalence means equivalence could not be determined
	UnknownEquivalence Equivalence = iota
	// NoEquivalence means means there was no matching record of any kind in Dynamo
	NoEquivalence
	// IDEquivalence means a record with the same ID as the subject was found, but one
	// or more of its other fields did not match the subject
	IDEquivalence
	// BindingEquivalence means a record that matched all of the fields of the
	// subject was found
	BindingEquivalence
)

// InitDynamo initialzes the dynamo database connection
func (c *Server) InitDynamo() {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	config := &aws.Config{
		Region:   aws.String("us-west-2"),
		Endpoint: aws.String(c.dbConfig.DynamodbEndpoint),
	}

	if os.Getenv("ENV") != "production" {
		config.DisableSSL = aws.Bool(true)
	}

	svc := dynamodb.New(sess, config)
	c.dynamo = svc
}

// primaryDynamoTable returns the primary DynamoDB table name, or empty string if not configured.
func primaryDynamoTable() string {
	return os.Getenv("dynamodb_table")
}

// legacyDynamoTable returns the legacy DynamoDB table name.
// Falls back to "redemptions" so deployments without explicit configuration are unaffected.
func legacyDynamoTable() string {
	if v, ok := os.LookupEnv("dynamodb_table_legacy"); ok {
		return v
	}

	return "redemptions"
}

// redemptionTTL returns the Unix timestamp to use as the DynamoDB TTL for a redemption record.
// When the issuer has no expiry, it falls back to 6 months from now so that DynamoDB can
// sweep the record rather than retaining it indefinitely.
func redemptionTTL(issuer *model.Issuer) int64 {
	if t := issuer.ExpiresAtTime(); !t.IsZero() {
		return t.Unix()
	}
	return time.Now().AddDate(0, 6, 0).Unix()
}

// redemptionWriteTable returns the table to use for new redemption writes.
func redemptionWriteTable() string {
	if t := primaryDynamoTable(); t != "" {
		return t
	}
	return legacyDynamoTable()
}

// fetchRedemptionV2 takes a UUID v5 which is used to fetch and return a RedemptionV2 record.
// It checks the primary table first (if configured), then falls back to the legacy table with
// a warning so that tokens issued against the old table continue to be honoured during migration.
func (c *Server) fetchRedemptionV2(id uuid.UUID) (*RedemptionV2, error) {
	if primary := primaryDynamoTable(); primary != "" {
		redemption, err := c.fetchRedemptionV2FromTable(id, primary)
		if err == nil {
			return redemption, nil
		}
		if !errors.Is(err, errRedemptionNotFound) {
			return nil, err
		}
		c.Logger.Info("redemption not found in primary table, checking legacy table", "id", id)
	}
	return c.fetchRedemptionV2FromTable(id, legacyDynamoTable())
}

// fetchRedemptionV2FromTable fetches a RedemptionV2 record from the named DynamoDB table.
func (c *Server) fetchRedemptionV2FromTable(id uuid.UUID, tableName string) (*RedemptionV2, error) {
	input := &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(id.String()),
			},
		},
	}
	result, err := c.dynamo.GetItem(input)
	if err != nil {
		c.Logger.Error("Unable to get item")
		return nil, err
	}

	redemption := RedemptionV2{}

	err = dynamodbattribute.UnmarshalMap(result.Item, &redemption)
	if err != nil {
		c.Logger.Error("Unable to unmarshal redemption")
		panic(err)
	}

	if redemption.IssuerID == "" || redemption.ID == "" {
		return nil, errRedemptionNotFound
	}
	return &redemption, nil
}

func (c *Server) redeemTokenWithDynamo(issuer *model.Issuer, preimage *crypto.TokenPreimage, payload string, offset int64) error {
	preimageTxt, err := preimage.MarshalText()
	if err != nil {
		c.Logger.Error("Error Marshalling preimage")
		return err
	}

	id := uuid.NewSHA1(*issuer.ID, []byte(string(preimageTxt)))

	redemption := RedemptionV2{
		IssuerID:  issuer.ID.String(),
		ID:        id.String(),
		PreImage:  string(preimageTxt),
		Payload:   payload,
		Timestamp: time.Now(),
		TTL:       redemptionTTL(issuer),
		Offset:    offset,
	}

	av, err := dynamodbattribute.MarshalMap(redemption)
	if err != nil {
		c.Logger.Error("Error marshalling redemption")
		return err
	}

	input := &dynamodb.PutItemInput{
		Item:                av,
		ConditionExpression: aws.String("attribute_not_exists(id)"),
		TableName:           aws.String(redemptionWriteTable()),
	}

	_, err = c.dynamo.PutItem(input)
	if err != nil {
		if err, ok := err.(awserr.Error); ok && err.Code() == "ConditionalCheckFailedException" { // unique constraint violation
			c.Logger.Error("Duplicate redemption")
			return errDuplicateRedemption
		}
		c.Logger.Error("Error creating item")
		return err
	}
	return nil
}

// PersistRedemption saves the redemption in the database
func (c *Server) PersistRedemption(redemption RedemptionV2) error {
	av, err := dynamodbattribute.MarshalMap(redemption)
	if err != nil {
		c.Logger.Error("Error marshalling redemption")
		return err
	}

	input := &dynamodb.PutItemInput{
		Item:                av,
		ConditionExpression: aws.String("attribute_not_exists(id)"),
		TableName:           aws.String(redemptionWriteTable()),
	}

	_, err = c.dynamo.PutItem(input)
	if err != nil {
		if err, ok := err.(awserr.Error); ok && err.Code() == "ConditionalCheckFailedException" { // unique constraint violation
			c.Logger.Error("Duplicate redemption")
			return errDuplicateRedemption
		}
		c.Logger.Error("Error creating item")
		return err
	}
	return nil
}

// CheckRedeemedTokenEquivalence returns whether just the ID of a given RedemptionV2 token
// matches an existing persisted record, the whole value matches, or neither match and
// this is a new token to be redeemed.
func (c *Server) CheckRedeemedTokenEquivalence(issuer *model.Issuer, preimage *crypto.TokenPreimage, payload string, offset int64) (*RedemptionV2, Equivalence, error) {
	temporary := false
	preimageTxt, err := preimage.MarshalText()
	if err != nil {
		c.Logger.Error("Error Marshalling preimage")
		return nil, UnknownEquivalence, utils.ProcessingErrorFromError(err, temporary)
	}

	id := uuid.NewSHA1(*issuer.ID, preimageTxt)

	redemption := RedemptionV2{
		IssuerID:  issuer.ID.String(),
		ID:        id.String(),
		PreImage:  string(preimageTxt),
		Payload:   payload,
		Timestamp: time.Now(),
		TTL:       redemptionTTL(issuer),
	}

	existingRedemption, err := c.fetchRedemptionV2(*issuer.ID)

	// If err is nil that means that the record does exist in the database and we need
	// to determine whether the body is equivalent to what was provided or just the
	// id.
	if err == nil {
		if redemption.Payload == existingRedemption.Payload {
			return &redemption, BindingEquivalence, nil
		}
		return &redemption, IDEquivalence, nil
	}
	if errors.Is(err, errRedemptionNotFound) {
		return &redemption, NoEquivalence, nil
	}

	var (
		ptee *awsDynamoTypes.ProvisionedThroughputExceededException
		rle  *awsDynamoTypes.RequestLimitExceeded
		ise  *awsDynamoTypes.InternalServerError
	)

	// is this a temporary error?
	if errors.As(err, &ptee) ||
		errors.As(err, &rle) ||
		errors.As(err, &ise) {
		temporary = true
	}
	return &redemption, NoEquivalence, utils.ProcessingErrorFromError(err, temporary)
}
