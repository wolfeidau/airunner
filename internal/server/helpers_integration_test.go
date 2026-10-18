//go:build integration

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wolfeidau/airunner/internal/auth"
	"github.com/wolfeidau/airunner/internal/store"
	"github.com/wolfeidau/airunner/internal/store/postgres/postgrestest"
)

// serverURLs holds endpoints that inject a fixed fixture principal.
type serverURLs struct {
	User   string
	Worker string
}

// principalServer serves handler with caller injected as the authenticated principal.
func principalServer(t testing.TB, handler http.Handler, caller store.Caller, roles []string, typ string) string {
	t.Helper()
	principal := &auth.Principal{PrincipalID: caller.PrincipalID, OrgID: caller.OrgID, Roles: roles, Type: typ}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), principal)))
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

// newPostgresServers builds a server on a fresh PostgreSQL database and returns
// one endpoint per fixture principal.
func newPostgresServers(t testing.TB) (*postgrestest.Stores, postgrestest.Fixture, serverURLs) {
	t.Helper()
	stores := postgrestest.NewStores(t)
	fx := postgrestest.SeedOrg(t, stores)
	handler := NewServer(stores.Jobs).Handler()
	return stores, fx, serverURLs{
		User:   principalServer(t, handler, fx.User, []string{"user"}, "user"),
		Worker: principalServer(t, handler, fx.Worker, []string{"worker"}, "worker"),
	}
}
