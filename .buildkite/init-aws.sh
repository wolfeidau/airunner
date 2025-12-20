#!/bin/bash
set -e

echo "Creating SQS queues..."

# Create default queue
awslocal sqs create-queue --queue-name airunner-test-default

# Create priority queue
awslocal sqs create-queue --queue-name airunner-test-priority

echo "SQS queues created successfully"
awslocal sqs list-queues
