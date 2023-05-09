//go:build mage

// Welcome to the SBOM policy enforcement example.
package main

import (
	"context"
	"fmt"
	"os"

	"dagger.io/dagger"
	"github.com/magefile/mage/mg"
	"github.com/sirupsen/logrus"

	"github.com/RealHarshThakur/sbom-policies/license"
	"github.com/RealHarshThakur/sbom-policies/vulnerability"

	"github.com/RealHarshThakur/sbom-policies/sbom"
)

type Policy mg.Namespace

var l = SetupLogging()

// Check will extract SBOM from OCI and check if it complies with the license and vulnerability policies.
func (Policy) Check(ctx context.Context, image string) error {
	client, err := dagger.Connect(ctx, dagger.WithLogOutput(os.Stdout))
	if err != nil {
		return err
	}

	l.Info("Generating SBOM for OCI:", image)
	err = sbom.Generate(ctx, client, image)
	if err != nil {
		return err
	}
	l.Info("SBOM generated for OCI:", image)

	l.Info("Checking license compliance for:", image)
	err = LicenseCheck(ctx, "/tmp/artifacts/sbom.json")
	if err != nil {
		return err
	}
	l.Info("License check passed for:", image)

	l.Info("Checking vulnerability compliance for:", image)
	err = vulnerability.GenerateV(ctx, client, image)
	if err != nil {
		return err
	}

	err = VulnerabilityCheck(ctx, "/tmp/artifacts/vuln.json")
	if err != nil {
		return err
	}
	l.Info("Vulnerability check passed for:", image)

	return nil
}

// LicenseCheck checks the license of the SBOM, accepts the SBOM file path as input, assumes OPA server is running on localhost:8181.
func LicenseCheck(ctx context.Context, fileName string) error {
	url := "http://localhost:8181/v1/data/license"
	resp, err := license.Check(url, fileName)
	if err != nil {
		return err
	}

	if len(resp.Result.Deny) > 0 {
		for _, deny := range resp.Result.Deny {
			l.Errorf("Package %s has prohibited license %s", deny.Package, deny.ProhibitedLicense)
		}
		return fmt.Errorf("license check failed")
	}

	if len(resp.Result.Warn) > 0 {
		for _, warn := range resp.Result.Warn {
			l.Warnf("Package %s has license %s that needs to be reviewed", warn.Package, warn.ReviewLicense)
		}
		return nil
	}

	return nil
}

func VulnerabilityCheck(ctx context.Context, fileName string) error {
	url := "http://localhost:8181/v1/data/vuln"
	resp, err := vulnerability.Check(url, fileName)
	if err != nil {
		return err
	}

	var counter int
	if len(resp.Result.Deny) > 0 {
		for _, deny := range resp.Result.Deny {
			for _, pkgName := range deny.Critical {
				counter++
				l.Errorf("Package %s has critical vulnerability", pkgName)
			}
			for _, pkgName := range deny.High {
				counter++
				l.Errorf("Package %s has high vulnerability", pkgName)
			}
			for _, pkgName := range deny.Medium {
				counter++
				l.Errorf("Package %s has medium vulnerability", pkgName)
			}
			for _, pkgName := range deny.Low {
				counter++
				l.Errorf("Package %s has low vulnerability", pkgName)
			}
			for _, pkgName := range deny.Negligible {
				counter++
				l.Errorf("Package %s has negligible vulnerability", pkgName)
			}
		}
	}
	if counter > 0 {
		l.Error(fmt.Sprintf("Vulnerability check failed, found %d vulnerable packages", counter))
		return fmt.Errorf("vulnerability check failed")
	}

	return nil
}

// SetupLogging sets up the logging for the router daemon
func SetupLogging() *logrus.Logger {
	// Logging create logging object
	log := logrus.New()
	log.SetOutput(os.Stdout)
	log.SetLevel(logrus.DebugLevel)
	return log
}
