package testutil

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// StartPostgresContainer starts a Postgres container for DB integration tests.
// This implementation uses the Docker CLI because the intern/sina commit hook
// does not allow committing go.mod/go.sum changes for testcontainers-go yet.
func StartPostgresContainer(ctx context.Context) (string, func(), error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return "", nil, fmt.Errorf("docker CLI not found in PATH: %w", err)
	}

	name := fmt.Sprintf("upspa_test_pg_%d", time.Now().UnixNano())
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "-d", "-p", "0:5432", "--name", name,
		"-e", "POSTGRES_USER=test", "-e", "POSTGRES_PASSWORD=test", "-e", "POSTGRES_DB=test", "postgres:15-alpine")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", nil, fmt.Errorf("docker run failed: %w: %s", err, string(out))
	}

	containerID := strings.TrimSpace(string(out))
	cleanup := func() {
		_ = exec.Command("docker", "rm", "-f", containerID).Run()
	}

	hostPort, err := waitForMappedPort(containerID)
	if err != nil {
		cleanup()
		return "", nil, err
	}

	dsn := fmt.Sprintf("postgres://test:test@127.0.0.1:%s/test?sslmode=disable", hostPort)
	return dsn, cleanup, nil
}

func waitForMappedPort(containerID string) (string, error) {
	deadline := time.After(60 * time.Second)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-deadline:
			return "", errors.New("timeout waiting for container port mapping")
		case <-tick.C:
			out, _ := exec.Command("docker", "port", containerID, "5432").CombinedOutput()
			if len(out) == 0 {
				continue
			}

			parts := strings.Split(strings.TrimSpace(string(out)), ":")
			hostPort := parts[len(parts)-1]
			if hostPort != "" {
				return hostPort, nil
			}
		}
	}
}
