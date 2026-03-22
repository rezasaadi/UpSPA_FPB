package config

import (
	"log"
	"os"
	"strconv"
)

// Config holds the core settings required to run the server.
type Config struct {
	Port        string
	DatabaseURL string
	SpID        uint32
}

// Load reads settings from the operating system environment.
// If a value is missing, it falls back to local development defaults.
func Load() *Config {
	// 1. PORT setting
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Use port 8080 for local development.
	}

	// 2. DATABASE_URL setting
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		// Temporary local address until the database setup is ready.
		dbURL = "postgres://postgres:postgres@localhost:5432/upspa?sslmode=disable"
	}

	// 3. SP_ID (Storage Provider ID) setting
	spIDStr := os.Getenv("SP_ID")
	var spID uint32 = 1 // Default SP ID for local development.

	if spIDStr != "" {
		// Convert the environment string value to the uint32 type used by the models.
		parsedID, err := strconv.ParseUint(spIDStr, 10, 32)
		if err != nil {
			log.Printf("Warning: invalid SP_ID setting (%s). Default value (1) will be used.\n", spIDStr)
		} else {
			spID = uint32(parsedID)
		}
	}

	// Return all resolved settings in a single struct.
	return &Config{
		Port:        port,
		DatabaseURL: dbURL,
		SpID:        spID,
	}
}