package server

import (
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr" // nolint
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
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

	var config = &aws.Config{
		Region:   aws.String("us-west-2"),
		Endpoint: aws.String(c.dbConfig.DynamodbEndpoint),
	}

	if os.Getenv("ENV") != "production" {
		config.DisableSSL = aws.Bool(true)
	}

	svc := dynamodb.New(sess, config)
	c.dynamo = svc
}

// fetchRedemptionV2 takes a UUID v5 which is used to fetch and return a RedemptionV2 record
func (c *Server) fetchRedemptionV2(id uuid.UUID) (*RedemptionV2, error) {
	tableName := "redemptions"
	if os.Getenv("dynamodb_table") != "" {
		tableName = os.Getenv("dynamodb_table")
	}

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

func (c *Server) redeemTokenWithDynamo(issuer *Issuer, preimage *crypto.TokenPreimage, payload string) error {
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
		TTL:       issuer.ExpiresAt.Unix(),
	}

	av, err := dynamodbattribute.MarshalMap(redemption)
	if err != nil {
		c.Logger.Error("Error marshalling redemption")
		return err
	}

	input := &dynamodb.PutItemInput{
		Item:                av,
		ConditionExpression: aws.String("attribute_not_exists(id)"),
		TableName:           aws.String("redemptions"),
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
		TableName:           aws.String("redemptions"),
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
func (c *Server) CheckRedeemedTokenEquivalence(issuer *Issuer, preimage *crypto.TokenPreimage, payload string) (*RedemptionV2, Equivalence, error) {
	preimageTxt, err := preimage.MarshalText()
	if err != nil {
		c.Logger.Error("Error Marshalling preimage")
		return nil, UnknownEquivalence, err
	}

	id := uuid.NewSHA1(*issuer.ID, preimageTxt)

	redemption := RedemptionV2{
		IssuerID:  issuer.ID.String(),
		ID:        id.String(),
		PreImage:  string(preimageTxt),
		Payload:   payload,
		Timestamp: time.Now(),
		TTL:       issuer.ExpiresAt.Unix(),
	}

	existingRedemption, err := c.fetchRedemptionV2(*issuer.ID)

	// If err is nil that means that the record does exist in the database and we need
	// to determine whether the body is equivalent to what was provided or just the
	// id.
	if err == nil {
		if redemption.Payload == *&existingRedemption.Payload {
			return &redemption, BindingEquivalence, nil
		}
		return &redemption, IDEquivalence, nil
	}
	return &redemption, NoEquivalence, nil
}
