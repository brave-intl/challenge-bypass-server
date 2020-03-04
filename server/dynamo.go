package server

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
)

func (c *Server) initDynamo() {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	svc := dynamodb.New(sess, &aws.Config{
		Region:                        aws.String("us-west-2"),
		Endpoint:                      aws.String(c.dbConfig.DynamodbEndpoint),
		CredentialsChainVerboseErrors: aws.Bool(true),
	})

	c.dynamo = svc
}

func (c *Server) fetchRedemptionV2(issuer *Issuer, ID string) (*RedemptionV2, error) {
	input := &dynamodb.GetItemInput{
		TableName: aws.String("redemptions"),
		Key: map[string]*dynamodb.AttributeValue{
			"issuerId": {
				S: aws.String(issuer.ID),
			}, "id": {
				S: aws.String(ID),
			},
		},
	}
	result, err := c.dynamo.GetItem(input)
	if err != nil {
		return nil, err
	}

	redemption := RedemptionV2{}

	err = dynamodbattribute.UnmarshalMap(result.Item, &redemption)
	if err != nil {
		panic(err)
	}

	if redemption.IssuerID == "" {
		return nil, errRedemptionNotFound
	}
	return &redemption, nil
}

func (c *Server) redeemTokenV2(issuer *Issuer, preimage *crypto.TokenPreimage, payload string) error {
	preimageTxt, err := preimage.MarshalText()
	redemption := RedemptionV2{
		IssuerID: issuer.ID,
		ID:       string(preimageTxt),
		Payload:  payload,
		TTL:      issuer.ExpiresAt.Unix(),
	}

	av, err := dynamodbattribute.MarshalMap(redemption)
	if err != nil {
		return err
	}

	input := &dynamodb.PutItemInput{
		Item:                av,
		ConditionExpression: aws.String("attribute_not_exists(issuerId) AND attribute_not_exists(id)"),
		TableName:           aws.String("redemptions"),
	}

	_, err = c.dynamo.PutItem(input)
	if err != nil {
		if err, ok := err.(awserr.Error); ok && err.Code() == "ConditionalCheckFailedException" { // unique constraint violation
			return errDuplicateRedemption
		}
		return err
	}

	return nil
}
