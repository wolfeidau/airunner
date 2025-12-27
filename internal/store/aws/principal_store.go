package aws

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
	"github.com/wolfeidau/airunner/internal/store"
)

// PrincipalStore is a DynamoDB implementation of PrincipalStore
type PrincipalStore struct {
	client    *dynamodb.Client
	tableName string
}

// NewPrincipalStore creates a new DynamoDB principal store
func NewPrincipalStore(client *dynamodb.Client, tableName string) *PrincipalStore {
	return &PrincipalStore{
		client:    client,
		tableName: tableName,
	}
}

// Get retrieves principal metadata by ID
func (s *PrincipalStore) Get(ctx context.Context, principalID string) (*store.PrincipalMetadata, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"principal_id": &types.AttributeValueMemberS{Value: principalID},
		},
	})
	if err != nil {
		return nil, wrapAWSError(err, "failed to get principal")
	}

	if result.Item == nil {
		return nil, store.ErrPrincipalNotFound
	}

	var principal store.PrincipalMetadata
	if err := attributevalue.UnmarshalMap(result.Item, &principal); err != nil {
		return nil, fmt.Errorf("failed to unmarshal principal: %w", err)
	}

	return &principal, nil
}

// Create creates a new principal
func (s *PrincipalStore) Create(ctx context.Context, principal *store.PrincipalMetadata) error {
	item, err := attributevalue.MarshalMap(principal)
	if err != nil {
		return fmt.Errorf("failed to marshal principal: %w", err)
	}

	// Use ConditionExpression to prevent duplicates
	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.tableName),
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(principal_id)"),
	})
	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return store.ErrPrincipalAlreadyExists
		}
		return wrapAWSError(err, "failed to create principal")
	}

	log.Debug().
		Str("principal_id", principal.PrincipalID).
		Str("type", string(principal.Type)).
		Msg("principal created")

	return nil
}

// Update updates principal metadata
func (s *PrincipalStore) Update(ctx context.Context, principal *store.PrincipalMetadata) error {
	item, err := attributevalue.MarshalMap(principal)
	if err != nil {
		return fmt.Errorf("failed to marshal principal: %w", err)
	}

	// Use ConditionExpression to ensure principal exists
	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.tableName),
		Item:                item,
		ConditionExpression: aws.String("attribute_exists(principal_id)"),
	})
	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return store.ErrPrincipalNotFound
		}
		return wrapAWSError(err, "failed to update principal")
	}

	log.Debug().
		Str("principal_id", principal.PrincipalID).
		Msg("principal updated")

	return nil
}

// Suspend suspends a principal
func (s *PrincipalStore) Suspend(ctx context.Context, principalID string, reason string) error {
	now := time.Now()

	update := expression.Set(
		expression.Name("status"),
		expression.Value(store.PrincipalStatusSuspended),
	).Set(
		expression.Name("suspended_at"),
		expression.Value(now),
	).Set(
		expression.Name("suspended_reason"),
		expression.Value(reason),
	)

	condition := expression.AttributeExists(expression.Name("principal_id"))

	expr, err := expression.NewBuilder().
		WithUpdate(update).
		WithCondition(condition).
		Build()
	if err != nil {
		return fmt.Errorf("failed to build expression: %w", err)
	}

	_, err = s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.tableName),
		Key:                       map[string]types.AttributeValue{"principal_id": &types.AttributeValueMemberS{Value: principalID}},
		UpdateExpression:          expr.Update(),
		ConditionExpression:       expr.Condition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	})
	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return store.ErrPrincipalNotFound
		}
		return wrapAWSError(err, "failed to suspend principal")
	}

	log.Info().
		Str("principal_id", principalID).
		Str("reason", reason).
		Msg("principal suspended")

	return nil
}

// Activate activates a suspended principal
func (s *PrincipalStore) Activate(ctx context.Context, principalID string) error {
	update := expression.Set(
		expression.Name("status"),
		expression.Value(store.PrincipalStatusActive),
	).Remove(
		expression.Name("suspended_at"),
	).Remove(
		expression.Name("suspended_reason"),
	)

	condition := expression.AttributeExists(expression.Name("principal_id"))

	expr, err := expression.NewBuilder().
		WithUpdate(update).
		WithCondition(condition).
		Build()
	if err != nil {
		return fmt.Errorf("failed to build expression: %w", err)
	}

	_, err = s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.tableName),
		Key:                       map[string]types.AttributeValue{"principal_id": &types.AttributeValueMemberS{Value: principalID}},
		UpdateExpression:          expr.Update(),
		ConditionExpression:       expr.Condition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	})
	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return store.ErrPrincipalNotFound
		}
		return wrapAWSError(err, "failed to activate principal")
	}

	log.Info().
		Str("principal_id", principalID).
		Msg("principal activated")

	return nil
}

// Delete soft-deletes a principal
func (s *PrincipalStore) Delete(ctx context.Context, principalID string) error {
	update := expression.Set(
		expression.Name("status"),
		expression.Value(store.PrincipalStatusDeleted),
	)

	condition := expression.AttributeExists(expression.Name("principal_id"))

	expr, err := expression.NewBuilder().
		WithUpdate(update).
		WithCondition(condition).
		Build()
	if err != nil {
		return fmt.Errorf("failed to build expression: %w", err)
	}

	_, err = s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.tableName),
		Key:                       map[string]types.AttributeValue{"principal_id": &types.AttributeValueMemberS{Value: principalID}},
		UpdateExpression:          expr.Update(),
		ConditionExpression:       expr.Condition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	})
	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return store.ErrPrincipalNotFound
		}
		return wrapAWSError(err, "failed to delete principal")
	}

	log.Info().
		Str("principal_id", principalID).
		Msg("principal deleted")

	return nil
}

// List returns principals matching filters
func (s *PrincipalStore) List(ctx context.Context, opts store.ListPrincipalsOptions) ([]*store.PrincipalMetadata, error) {
	var input *dynamodb.ScanInput

	// Build filter expression
	var filterBuilder expression.ConditionBuilder
	hasFilter := false

	if opts.Type != "" {
		filterBuilder = expression.Name("type").Equal(expression.Value(opts.Type))
		hasFilter = true
	}

	if opts.Status != "" {
		statusFilter := expression.Name("status").Equal(expression.Value(opts.Status))
		if hasFilter {
			filterBuilder = filterBuilder.And(statusFilter)
		} else {
			filterBuilder = statusFilter
			hasFilter = true
		}
	}

	if hasFilter {
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
		return nil, wrapAWSError(err, "failed to list principals")
	}

	principals := make([]*store.PrincipalMetadata, 0, len(result.Items))
	for _, item := range result.Items {
		var principal store.PrincipalMetadata
		if err := attributevalue.UnmarshalMap(item, &principal); err != nil {
			log.Error().Err(err).Msg("failed to unmarshal principal, skipping")
			continue
		}
		principals = append(principals, &principal)
	}

	return principals, nil
}
