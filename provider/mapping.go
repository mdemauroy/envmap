package provider

import (
	"context"
	"fmt"
)

// CollectMappedSecrets fetches secrets using the mapping configuration.
// It groups entries by path to minimize API calls, then extracts the specific
// key for each env var from the returned map.
func CollectMappedSecrets(ctx context.Context, p MultiKeyProvider, mapping map[string]SecretMapping) (map[string]SecretRecord, error) {
	// Group env vars by Vault path to deduplicate reads.
	type entry struct {
		envVar string
		key    string
	}
	byPath := make(map[string][]entry)
	for envVar, sm := range mapping {
		byPath[sm.Path] = append(byPath[sm.Path], entry{envVar: envVar, key: sm.Key})
	}

	out := make(map[string]SecretRecord, len(mapping))

	for path, entries := range byPath {
		data, err := p.ReadSecret(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("read secret at %s: %w", path, err)
		}

		for _, e := range entries {
			val, ok := data[e.key]
			if !ok {
				return nil, fmt.Errorf("key %q not found in secret at path %q (env var %s)", e.key, path, e.envVar)
			}
			out[e.envVar] = SecretRecord{Value: val}
		}
	}

	return out, nil
}
