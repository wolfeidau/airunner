package postgres

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func validConfig() *JobStoreConfig {
	c := &JobStoreConfig{TokenSigningSecret: []byte("test-secret-key-min-32-bytes-long")}
	c.ApplyDefaults()
	return c
}

func TestConfig_RetentionDefaults(t *testing.T) {
	c := validConfig()
	require.Equal(t, 90*24*time.Hour, c.JobRetention)
	require.Equal(t, 30*24*time.Hour, c.EventRetention)
	require.Equal(t, time.Hour, c.RetentionInterval)
	require.NoError(t, c.Validate())
}

func TestConfig_EventRetentionZeroWithExplicitJobRetention(t *testing.T) {
	c := &JobStoreConfig{TokenSigningSecret: []byte("test-secret-key-min-32-bytes-long"), JobRetention: 24 * time.Hour}
	c.ApplyDefaults()
	require.Zero(t, c.EventRetention)
	require.NoError(t, c.Validate())
}

func TestConfig_RetentionValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*JobStoreConfig)
	}{
		{"event exceeds job", func(c *JobStoreConfig) { c.EventRetention = c.JobRetention + time.Second }},
		{"job negative", func(c *JobStoreConfig) { c.JobRetention = -time.Hour }},
		{"job zero", func(c *JobStoreConfig) { c.JobRetention = 0 }},
		{"interval negative", func(c *JobStoreConfig) { c.RetentionInterval = -time.Second }},
		{"interval zero", func(c *JobStoreConfig) { c.RetentionInterval = 0 }},
		{"event negative", func(c *JobStoreConfig) { c.EventRetention = -time.Second }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.mutate(c)
			require.Error(t, c.Validate())
		})
	}
}

func TestConfig_DisableRetentionLoop(t *testing.T) {
	secret := []byte("test-secret-key-min-32-bytes-long")

	c := &JobStoreConfig{TokenSigningSecret: secret, DisableRetentionLoop: true}
	c.ApplyDefaults()
	require.Zero(t, c.RetentionInterval)
	require.NoError(t, c.Validate())

	c = &JobStoreConfig{TokenSigningSecret: secret, DisableRetentionLoop: true, RetentionInterval: -time.Second}
	c.ApplyDefaults()
	require.Error(t, c.Validate())

	c = &JobStoreConfig{TokenSigningSecret: secret}
	c.ApplyDefaults()
	require.Equal(t, time.Hour, c.RetentionInterval)
	require.NoError(t, c.Validate())

	c.RetentionInterval = 0
	require.Error(t, c.Validate())
}
