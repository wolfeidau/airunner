# run tasks in lambda

The goals of this feature are:

1. Add a feature in the orchestrator which can prepare and launch jobs in AWS lambda.
  a) Jobs running in lambda will have access a limited set of permissions, with access to any tokens they need in AWS SSM parameter store, and write to an s3 bucket with a configured prefix specific to that job.
2. Before running a job a container will be prepared and pushed to AWS ECR, which contains code and any supporting packages or configuration. MCP servers are bundled into the container.
3. Lambda runs the agent, which spawns agents such as claude code, or codex cli, and when these complete, or the timeout is close, the agent will gather the resulting logs and upload them to S3. 
4. THe agent needs to be runnable locally via docker, with env vars for AWS credentials being passed into the container so it can simulate running in lambda for local testing and verification.
