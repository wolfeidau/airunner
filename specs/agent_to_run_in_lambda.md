# run tasks in lambda

The goals of this feature are:

1. Add a feature in the orchestrator which can prepare and launch jobs in AWS lambda.
  a) Jobs running in lambda will have access a limited set of permissions, with access to any tokens they need in AWS SSM parameter store, and write to an s3 bucket with a configured prefix specific to that job.
2. Before running a job a container will be prepared and pushed to AWS ECR, which contains code and any supporting packages or configuration. MCP servers are bundled into the container.
3. Lambda runs the agent, which spawns agents such as claude code, or codex cli, and when these complete, or the timeout is close, the agent will gather the resulting logs and upload them to S3. 
4. THe agent needs to be runnable locally via docker, with env vars for AWS credentials being passed into the container so it can simulate running in lambda for local testing and verification.

# Questions

Looking at the specification for running tasks in Lambda, I have several clarifying questions
   to ensure we build the right solution:

  Customer Problem & Use Cases

  1. What specific workloads are we targeting for Lambda execution? Are these CPU-intensive
  jobs, I/O-bound tasks, or mixed workloads?
  2. What's the expected job duration range? Lambda has a 15-minute timeout - how does this
  constraint affect our design?
  3. What triggers job execution - API calls, scheduled events, or external systems?

  Technical Architecture

  4. Container strategy: Should we build one universal container with all MCP servers, or
  separate containers per job type? How do we handle container size limits (10GB uncompressed)?
  5. State management: How do we handle job state during execution? Do jobs need to checkpoint
  progress or are they atomic operations?
  6. Failure handling: What happens when Lambda times out or fails? Do we retry, restart, or
  mark as failed?

  AWS Integration

  7. IAM permissions model: What's the minimum viable permission set for Lambda jobs? Should
  each job type have different permission boundaries?
  8. SSM Parameter Store structure: How do we organize tokens/secrets? Per job type, per
  customer, or globally?
  9. S3 bucket organization: What's the prefix strategy - by job ID, timestamp, job type, or
  customer?

  Local Development

  10. Docker simulation: Should the local container exactly mirror Lambda's execution
  environment, or is functional equivalence sufficient?
  11. Development workflow: How do developers test changes before pushing containers to ECR?

  Operational Concerns

  12. Monitoring: What metrics and logs do we need to capture for operational visibility?
  13. Cost optimization: How do we prevent runaway costs from Lambda invocations?
  14. Scaling: What's the expected concurrency and how do we handle Lambda limits?

  Which of these areas should we dive deeper into first?
