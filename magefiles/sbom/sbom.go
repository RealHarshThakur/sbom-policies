package sbom

import (
	"context"

	"dagger.io/dagger"
)

// Generate generates SBOM for OCI artifact.
func Generate(ctx context.Context, client *dagger.Client, image string) error {
	_, err := client.Container().From("anchore/syft:latest").
		WithWorkdir("/tmp").
		Exec((dagger.ContainerExecOpts{
			Args: []string{image, "--scope", "all-layers", "-o", "spdx-json", "--file", "sbom.json"},
		})).
		Directory(".").
		Export(ctx, "/tmp/artifacts")
	if err != nil {
		return err
	}
	return nil
}