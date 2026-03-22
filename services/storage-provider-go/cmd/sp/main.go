package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
	"upspa/internal/api"
	"upspa/internal/config"
)

func main() {
	// Load configuration: determine the port and SP_ID for this server.
	cfg := config.Load()

	// Build the handler and the router setup.
	h := api.NewHandler(nil)
	router := api.NewRouter(h)

	// Construct the HTTP server and apply timeout protections.
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.Port),
		Handler:      router,
		ReadTimeout:  5 * time.Second,  // Maximum time allowed to read a request.
		WriteTimeout: 10 * time.Second, // Maximum time allowed to write a response.
		IdleTimeout:  15 * time.Second, // Maximum keep-alive idle time.
	}

	// Start listening for incoming requests.
	log.Printf("Storage Provider (SP) server is starting...")
	log.Printf("Port: %s | SP_ID: %d", cfg.Port, cfg.SpID)
	log.Printf("Database: %s", cfg.DatabaseURL)

	// ListenAndServe starts the server and blocks until it exits.
	err := srv.ListenAndServe()
	if err != nil {
		log.Fatalf("Server failed to start or crashed: %v", err)
	}
}