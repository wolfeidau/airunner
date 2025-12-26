package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/rs/zerolog/log"
)

// DynamoDBCertificateStore is a DynamoDB implementation of CertificateStore
type DynamoDBCertificateStore struct {
	client    *dynamodb.Client
	tableName string
}

// NewDynamoDBCertificateStore creates a new DynamoDB certificate store
func NewDynamoDBCertificateStore(client *dynamodb.Client, tableName string) *DynamoDBCertificateStore {
	return &DynamoDBCertificateStore{
		client:    client,
		tableName: tableName,
	}
}

// Get retrieves certificate metadata by serial number
func (s *DynamoDBCertificateStore) Get(ctx context.Context, serialNumber string) (*CertMetadata, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"serial_number": &types.AttributeValueMemberS{Value: serialNumber},
		},
	})
	if err != nil {
		return nil, wrapAWSError(err, "failed to get certificate")
	}

	if result.Item == nil {
		return nil, ErrCertNotFound
	}

	var cert CertMetadata
	if err := attributevalue.UnmarshalMap(result.Item, &cert); err != nil {
		return nil, fmt.Errorf("failed to unmarshal certificate: %w", err)
	}

	return &cert, nil
}

// GetByPrincipal retrieves all certificates for a principal using GSI1
func (s *DynamoDBCertificateStore) GetByPrincipal(ctx context.Context, principalID string) ([]*CertMetadata, error) {
	// Query GSI1 (principal_id as partition key)
	keyEx := expression.Key("principal_id").Equal(expression.Value(principalID))
	expr, err := expression.NewBuilder().WithKeyCondition(keyEx).Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build expression: %w", err)
	}

	result, err := s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:                 aws.String(s.tableName),
		IndexName:                 aws.String("GSI1"),
		KeyConditionExpression:    expr.KeyCondition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	})
	if err != nil {
		return nil, wrapAWSError(err, "failed to query certificates by principal")
	}

	certs := make([]*CertMetadata, 0, len(result.Items))
	for _, item := range result.Items {
		var cert CertMetadata
		if err := attributevalue.UnmarshalMap(item, &cert); err != nil {
			log.Error().Err(err).Msg("failed to unmarshal certificate, skipping")
			continue
		}
		certs = append(certs, &cert)
	}

	return certs, nil
}

// GetByFingerprint retrieves certificate by SHA-256 fingerprint using GSI2
func (s *DynamoDBCertificateStore) GetByFingerprint(ctx context.Context, fingerprint string) (*CertMetadata, error) {
	// Query GSI2 (fingerprint as partition key)
	keyEx := expression.Key("fingerprint").Equal(expression.Value(fingerprint))
	expr, err := expression.NewBuilder().WithKeyCondition(keyEx).Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build expression: %w", err)
	}

	result, err := s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:                 aws.String(s.tableName),
		IndexName:                 aws.String("GSI2"),
		KeyConditionExpression:    expr.KeyCondition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		Limit:                     aws.Int32(1),
	})
	if err != nil {
		return nil, wrapAWSError(err, "failed to query certificate by fingerprint")
	}

	if len(result.Items) == 0 {
		return nil, ErrCertNotFound
	}

	var cert CertMetadata
	if err := attributevalue.UnmarshalMap(result.Items[0], &cert); err != nil {
		return nil, fmt.Errorf("failed to unmarshal certificate: %w", err)
	}

	return &cert, nil
}

// Register stores certificate metadata
func (s *DynamoDBCertificateStore) Register(ctx context.Context, cert *CertMetadata) error {
	item, err := attributevalue.MarshalMap(cert)
	if err != nil {
		return fmt.Errorf("failed to marshal certificate: %w", err)
	}

	// Use ConditionExpression to prevent duplicates
	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.tableName),
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(serial_number)"),
	})
	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return ErrCertAlreadyExists
		}
		return wrapAWSError(err, "failed to register certificate")
	}

	log.Debug().
		Str("serial_number", cert.SerialNumber).
		Str("principal_id", cert.PrincipalID).
		Str("fingerprint", cert.Fingerprint).
		Msg("certificate registered")

	return nil
}

// Revoke marks a certificate as revoked
func (s *DynamoDBCertificateStore) Revoke(ctx context.Context, serialNumber string, reason string) error {
	now := time.Now()

	update := expression.Set(
		expression.Name("revoked"),
		expression.Value(true),
	).Set(
		expression.Name("revoked_at"),
		expression.Value(now),
	).Set(
		expression.Name("revocation_reason"),
		expression.Value(reason),
	)

	condition := expression.AttributeExists(expression.Name("serial_number"))

	expr, err := expression.NewBuilder().
		WithUpdate(update).
		WithCondition(condition).
		Build()
	if err != nil {
		return fmt.Errorf("failed to build expression: %w", err)
	}

	_, err = s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.tableName),
		Key:                       map[string]types.AttributeValue{"serial_number": &types.AttributeValueMemberS{Value: serialNumber}},
		UpdateExpression:          expr.Update(),
		ConditionExpression:       expr.Condition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	})
	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return ErrCertNotFound
		}
		return wrapAWSError(err, "failed to revoke certificate")
	}

	log.Info().
		Str("serial_number", serialNumber).
		Str("reason", reason).
		Msg("certificate revoked")

	return nil
}

// List returns all registered certificates
func (s *DynamoDBCertificateStore) List(ctx context.Context, opts ListCertificatesOptions) ([]*CertMetadata, error) {
	// If filtering by principal, use GSI1 for efficient query
	if opts.PrincipalID != "" {
		return s.GetByPrincipal(ctx, opts.PrincipalID)
	}

	// Otherwise, scan the table
	var input *dynamodb.ScanInput

	if !opts.IncludeRevoked {
		// Filter out revoked certificates
		filterBuilder := expression.Name("revoked").Equal(expression.Value(false))
		expr, err := expression.NewBuilder().WithFilter(filterBuilder).Build()
		if err != nil {
			return nil, fmt.Errorf("failed to build filter expression: %w", err)
		}

		input = &dynamodb.ScanInput{
			TableName:                 aws.String(s.tableName),
			FilterExpression:          expr.Filter(),
			ExpressionAttributeNames:  expr.Names(),
			ExpressionAttributeValues: expr.Values(),
		}
	} else {
		input = &dynamodb.ScanInput{
			TableName: aws.String(s.tableName),
		}
	}

	if opts.Limit > 0 {
		if opts.Limit > 2147483647 {
			input.Limit = aws.Int32(2147483647)
		} else {
			input.Limit = aws.Int32(int32(opts.Limit))
		}
	}

	result, err := s.client.Scan(ctx, input)
	if err != nil {
		return nil, wrapAWSError(err, "failed to list certificates")
	}

	certs := make([]*CertMetadata, 0, len(result.Items))
	for _, item := range result.Items {
		var cert CertMetadata
		if err := attributevalue.UnmarshalMap(item, &cert); err != nil {
			log.Error().Err(err).Msg("failed to unmarshal certificate, skipping")
			continue
		}
		certs = append(certs, &cert)
	}

	return certs, nil
}
