package bootstrap

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

// CreateQueues creates SQS queues for job processing
// If cleanResources is true, deletes existing queues first to ensure clean state
// If cleanResources is false, reuses existing queues (preserves data)
func CreateQueues(ctx context.Context, client *sqs.Client, env string, cleanResources bool) (map[string]string, error) {
	queueNames := map[string]string{
		"default":  fmt.Sprintf("%s-default", env),
		"priority": fmt.Sprintf("%s-priority", env),
	}

	queueURLs := make(map[string]string)

	for queueType, queueName := range queueNames {
		// If cleanResources is true, delete existing queue first
		if cleanResources {
			if err := deleteQueueIfExists(ctx, client, queueName); err != nil {
				return nil, fmt.Errorf("failed to delete existing queue %s: %w", queueName, err)
			}
		}

		// Try to create queue
		createResp, err := client.CreateQueue(ctx, &sqs.CreateQueueInput{
			QueueName: aws.String(queueName),
			Attributes: map[string]string{
				string(types.QueueAttributeNameVisibilityTimeout): "300", // 5 minutes
			},
		})
		if err != nil {
			// If queue already exists and we're not cleaning, get its URL instead
			if !cleanResources && (strings.Contains(err.Error(), "QueueAlreadyExists") || strings.Contains(err.Error(), "already exists")) {
				getURLResp, getErr := client.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{
					QueueName: aws.String(queueName),
				})
				if getErr != nil {
					return nil, fmt.Errorf("failed to get existing queue %s: %w", queueName, getErr)
				}
				queueURLs[queueType] = *getURLResp.QueueUrl
				continue
			}
			return nil, fmt.Errorf("failed to create queue %s: %w", queueName, err)
		}

		queueURLs[queueType] = *createResp.QueueUrl
	}

	return queueURLs, nil
}

// deleteQueueIfExists attempts to delete a queue if it exists
func deleteQueueIfExists(ctx context.Context, client *sqs.Client, queueName string) error {
	// Try to get queue URL
	getURLResp, err := client.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{
		QueueName: aws.String(queueName),
	})

	// If queue doesn't exist, we're done
	if err != nil {
		if strings.Contains(err.Error(), "NonExistentQueue") || strings.Contains(err.Error(), "does not exist") {
			return nil
		}
		// Unknown error
		return err
	}

	// Queue exists, delete it
	_, err = client.DeleteQueue(ctx, &sqs.DeleteQueueInput{
		QueueUrl: getURLResp.QueueUrl,
	})
	if err != nil {
		return err
	}

	// Wait a moment for deletion to propagate
	// SQS has eventual consistency
	time.Sleep(2 * time.Second)

	return nil
}

// DeleteQueues removes all queues created by CreateQueues
func DeleteQueues(ctx context.Context, client *sqs.Client, queueURLs map[string]string) error {
	for queueType, queueURL := range queueURLs {
		_, err := client.DeleteQueue(ctx, &sqs.DeleteQueueInput{
			QueueUrl: aws.String(queueURL),
		})
		if err != nil {
			return fmt.Errorf("failed to delete %s queue: %w", queueType, err)
		}
	}
	return nil
}
