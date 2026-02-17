package provider

import (
	"context"
	"fmt"
	"testing"
)

// mockMultiKeyProvider implements MultiKeyProvider for testing.
type mockMultiKeyProvider struct {
	secrets map[string]map[string]string
}

func (m *mockMultiKeyProvider) ReadSecret(_ context.Context, path string) (map[string]string, error) {
	data, ok := m.secrets[path]
	if !ok {
		return nil, fmt.Errorf("secret %s not found", path)
	}
	return data, nil
}

func TestCollectMappedSecrets(t *testing.T) {
	mock := &mockMultiKeyProvider{
		secrets: map[string]map[string]string{
			"shared/database": {
				"DB_USER":     "dbuser",
				"DB_PASSWORD": "dbpass",
			},
			"shared/cdn": {
				"CDN_TOKEN":  "tok123",
				"CDN_HEADER": "hdr456",
			},
			"myapp": {
				"API_SECRET_KEY": "sk-abc",
			},
		},
	}

	mapping := map[string]SecretMapping{
		"DB_USER":     {Path: "shared/database", Key: "DB_USER"},
		"DB_PASSWORD": {Path: "shared/database", Key: "DB_PASSWORD"},
		"CDN_TOKEN":   {Path: "shared/cdn", Key: "CDN_TOKEN"},
		"API_KEY":     {Path: "myapp", Key: "API_SECRET_KEY"}, // env var differs from vault key
	}

	records, err := CollectMappedSecrets(context.Background(), mock, mapping)
	if err != nil {
		t.Fatalf("CollectMappedSecrets: %v", err)
	}

	expected := map[string]string{
		"DB_USER":     "dbuser",
		"DB_PASSWORD": "dbpass",
		"CDN_TOKEN":   "tok123",
		"API_KEY":     "sk-abc",
	}

	if len(records) != len(expected) {
		t.Fatalf("got %d records, want %d", len(records), len(expected))
	}

	for k, want := range expected {
		rec, ok := records[k]
		if !ok {
			t.Errorf("missing key %q in results", k)
			continue
		}
		if rec.Value != want {
			t.Errorf("records[%q] value mismatch", k)
		}
	}
}

func TestCollectMappedSecrets_MissingKey(t *testing.T) {
	mock := &mockMultiKeyProvider{
		secrets: map[string]map[string]string{
			"shared/cdn": {
				"CDN_TOKEN": "tok123",
			},
		},
	}

	mapping := map[string]SecretMapping{
		"MISSING_VAR": {Path: "shared/cdn", Key: "NONEXISTENT_KEY"},
	}

	_, err := CollectMappedSecrets(context.Background(), mock, mapping)
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestCollectMappedSecrets_MissingPath(t *testing.T) {
	mock := &mockMultiKeyProvider{
		secrets: map[string]map[string]string{},
	}

	mapping := map[string]SecretMapping{
		"SOME_VAR": {Path: "nonexistent/path", Key: "SOME_KEY"},
	}

	_, err := CollectMappedSecrets(context.Background(), mock, mapping)
	if err == nil {
		t.Fatal("expected error for missing path")
	}
}

func TestCollectMappedSecrets_Empty(t *testing.T) {
	mock := &mockMultiKeyProvider{
		secrets: map[string]map[string]string{},
	}

	records, err := CollectMappedSecrets(context.Background(), mock, map[string]SecretMapping{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected empty map, got %d entries", len(records))
	}
}

func TestCollectMappedSecrets_DeduplicatesPaths(t *testing.T) {
	callCount := 0
	mock := &countingMultiKeyProvider{
		secrets: map[string]map[string]string{
			"shared/database": {
				"USER": "u",
				"PASS": "p",
			},
		},
		callCount: &callCount,
	}

	mapping := map[string]SecretMapping{
		"DB_USER": {Path: "shared/database", Key: "USER"},
		"DB_PASS": {Path: "shared/database", Key: "PASS"},
	}

	_, err := CollectMappedSecrets(context.Background(), mock, mapping)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if callCount != 1 {
		t.Errorf("ReadSecret called %d times, want 1 (should deduplicate by path)", callCount)
	}
}

// countingMultiKeyProvider tracks how many times ReadSecret is called.
type countingMultiKeyProvider struct {
	secrets   map[string]map[string]string
	callCount *int
}

func (m *countingMultiKeyProvider) ReadSecret(_ context.Context, path string) (map[string]string, error) {
	*m.callCount++
	data, ok := m.secrets[path]
	if !ok {
		return nil, fmt.Errorf("secret %s not found", path)
	}
	return data, nil
}
