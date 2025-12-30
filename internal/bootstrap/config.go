package bootstrap

import (
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

// Config holds configuration for bootstrapping LocalStack infrastructure
type Config struct {
	// AWS SDK clients
	SQSClient    *sqs.Client
	DynamoClient *dynamodb.Client

	// Resource naming
	Environment string // e.g., "dev", "test" - used as prefix for resource names

	// CleanResources controls whether to delete existing resources before creating
	// Set to false to preserve data across restarts (useful for development with live reload)
	CleanResources bool
}

// Resources holds identifiers for created infrastructure resources
type Resources struct {
	// Queue URLs by name ("default", "priority")
	QueueURLs map[string]string

	// DynamoDB table names
	TableNames struct {
		Jobs   string
		Events string
	}
}
