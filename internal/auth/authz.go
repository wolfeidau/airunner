package auth

import (
	"context"
	"errors"
	"slices"
	"strings"

	"connectrpc.com/connect"
	"github.com/rs/zerolog/log"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
)

// Role names used for authorization.
const (
	RoleAdmin  = "admin"
	RoleUser   = "user"
	RoleWorker = "worker"
)

// jobProcedureRoles maps each job and event procedure to the roles allowed to call it.
// Every RPC in JobService and JobEventsService must have an entry; unknown procedures
// under those services are denied.
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

var jobServicePrefixes = []string{
	"/" + jobv1connect.JobServiceName + "/",
	"/" + jobv1connect.JobEventsServiceName + "/",
}

// NewJobAuthzInterceptor returns an interceptor enforcing role-based access to the
// job and event services. Procedures outside those services pass through unchanged.
func NewJobAuthzInterceptor() connect.Interceptor {
	return &jobAuthzInterceptor{}
}

type jobAuthzInterceptor struct{}

// authorize returns nil if the call may proceed.
func (jobAuthzInterceptor) authorize(ctx context.Context, procedure string) error {
	roles, known := jobProcedureRoles[procedure]
	if !known && !hasJobServicePrefix(procedure) {
		return nil
	}

	principal := PrincipalFromContext(ctx)
	if principal == nil {
		log.Warn().Str("procedure", procedure).Msg("authz: no principal")
		return connect.NewError(connect.CodeUnauthenticated, ErrUnauthenticated)
	}

	if known && slices.ContainsFunc(principal.Roles, func(r string) bool { return slices.Contains(roles, r) }) {
		return nil
	}

	log.Warn().
		Str("procedure", procedure).
		Str("principal_id", principal.PrincipalID.String()).
		Str("org_id", principal.OrgID.String()).
		Msg("authz: permission denied")
	return connect.NewError(connect.CodePermissionDenied, errPermissionDenied)
}

func hasJobServicePrefix(procedure string) bool {
	return slices.ContainsFunc(jobServicePrefixes, func(p string) bool { return strings.HasPrefix(procedure, p) })
}

func (i jobAuthzInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if err := i.authorize(ctx, req.Spec().Procedure); err != nil {
			return nil, err
		}
		return next(ctx, req)
	}
}

func (jobAuthzInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (i jobAuthzInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if err := i.authorize(ctx, conn.Spec().Procedure); err != nil {
			return err
		}
		return next(ctx, conn)
	}
}

var errPermissionDenied = errors.New("permission denied")
