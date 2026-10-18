# Example: job authorization interceptor and error mapper

[← README](../README.md) | [← Bounded sweeps](bounded-sweeps.md) | [Reference model →](reference-model.md)

Source of truth: [authz.go](../../../internal/auth/authz.go) and [errors.go](../../../internal/server/errors.go)

These are excerpts, trimmed with `// ...`. If they differ from the source, the source wins. The role matrix and error map are summarised in [00-architecture.md](../00-architecture.md#tenancy-roles-and-errors) and specified in [03-phase3-tenancy-authz.md](../03-phase3-tenancy-authz.md).

## Role table

Every RPC in `JobService` and `JobEventsService` needs an entry. A coverage test fails when an RPC is added without one, and an unknown procedure under either service is denied (fail closed).

```go
var jobProcedureRoles = map[string][]string{
	jobv1connect.JobServiceEnqueueJobProcedure:             {RoleUser, RoleAdmin},
	jobv1connect.JobServiceListJobsProcedure:               {RoleUser, RoleAdmin},
	jobv1connect.JobServiceCancelJobProcedure:              {RoleUser, RoleAdmin},
	jobv1connect.JobEventsServiceStreamJobEventsProcedure:  {RoleUser, RoleAdmin},
	jobv1connect.JobServiceDequeueJobProcedure:             {RoleWorker, RoleAdmin},
	jobv1connect.JobServiceUpdateJobProcedure:              {RoleWorker, RoleAdmin},
	jobv1connect.JobServiceCompleteJobProcedure:            {RoleWorker, RoleAdmin},
	jobv1connect.JobEventsServicePublishJobEventsProcedure: {RoleWorker, RoleAdmin},
}
```

## Precedence

No principal is Unauthenticated. A principal without an allowed role, or an unknown procedure under a job service, is PermissionDenied. Procedures outside both services pass through. Each denial increments `authz.denied` with `procedure` and `reason`.

```go
func (i jobAuthzInterceptor) authorize(ctx context.Context, procedure string) error {
	roles, known := jobProcedureRoles[procedure]
	if !known && !hasJobServicePrefix(procedure) {
		return nil
	}

	principal := PrincipalFromContext(ctx)
	if principal == nil {
		log.Warn().Str("procedure", procedure).Msg("authz: no principal")
		i.countDenied(ctx, procedure, telemetry.ReasonUnauthenticated)
		return connect.NewError(connect.CodeUnauthenticated, ErrUnauthenticated)
	}

	if known && slices.ContainsFunc(principal.Roles, func(r string) bool { return slices.Contains(roles, r) }) {
		return nil
	}
	// ...
	i.countDenied(ctx, procedure, telemetry.ReasonForbidden)
	return connect.NewError(connect.CodePermissionDenied, errPermissionDenied)
}
```

## Unary and streaming wrappers

One check covers both transports.

```go
func (i jobAuthzInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if err := i.authorize(ctx, req.Spec().Procedure); err != nil {
			return nil, err
		}
		return next(ctx, req)
	}
}
// ...
func (i jobAuthzInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if err := i.authorize(ctx, conn.Spec().Procedure); err != nil {
			return err
		}
		return next(ctx, conn)
	}
}
```

## Error mapper

One mapper serves every job and event handler. Lease and not-found messages are generic so a caller cannot tell which check failed. `ErrJobCancelled` is tested before `ErrLeaseLost` because it wraps it.

```go
	switch {
	case errors.Is(err, store.ErrInvalidTaskToken),
		errors.Is(err, store.ErrInvalidArgument),
		errors.Is(err, store.ErrJobIDMismatch),
		errors.Is(err, store.ErrQueueMismatch):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, store.ErrEventTooLarge):
		return connect.NewError(connect.CodeResourceExhausted, err)
	case errors.Is(err, store.ErrJobNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, store.ErrJobCancelled):
		ce := connect.NewError(connect.CodeFailedPrecondition, err)
		ce.Meta().Set(leasereason.Header, leasereason.Cancelled)
		return ce
	case errors.Is(err, store.ErrFailedPrecondition),
		errors.Is(err, store.ErrLeaseLost):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, store.ErrConflict):
		return connect.NewError(connect.CodeAlreadyExists, err)
	// ...
	case errors.Is(err, store.ErrUnavailable):
		return connect.NewError(connect.CodeUnavailable, err)
	}
```

[← README](../README.md) | [← Bounded sweeps](bounded-sweeps.md) | [Reference model →](reference-model.md)
