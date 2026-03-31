// Command promptlock-server runs the PromptLock REST + gRPC server.
//
// Usage:
//
//	promptlock-server --http-port 8080 --level balanced --redact-pii
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/rajanyadav/promptlock/server"
	"google.golang.org/grpc"
)

func main() {
	var cfg server.Config
	flag.IntVar(&cfg.HTTPPort, "http-port", 8080, "HTTP/REST port")
	flag.IntVar(&cfg.GRPCPort, "grpc-port", 50051, "gRPC port")
	flag.StringVar(&cfg.Level, "level", "balanced", "Security level: basic, balanced, aggressive")
	flag.BoolVar(&cfg.RedactPII, "redact-pii", false, "Enable PII redaction")
	flag.StringVar(&cfg.OllamaURL, "ollama-url", "", "Ollama endpoint for vector detection")
	flag.StringVar(&cfg.OllamaModel, "ollama-model", "nomic-embed-text", "Ollama embedding model")
	flag.Parse()

	shield, err := server.NewShield(cfg)
	if err != nil {
		log.Fatalf("Failed to create shield: %v", err)
	}
	log.Printf("Shield: level=%s, pii=%v", cfg.Level, cfg.RedactPII)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// HTTP
	httpServer := server.NewHTTPServer(shield)
	httpAddr := fmt.Sprintf(":%d", cfg.HTTPPort)
	httpSrv := &http.Server{Addr: httpAddr, Handler: httpServer.Handler()}

	go func() {
		log.Printf("HTTP server listening on %s", httpAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP: %v", err)
		}
	}()

	// gRPC
	grpcAddr := fmt.Sprintf(":%d", cfg.GRPCPort)
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		log.Fatalf("gRPC listen: %v", err)
	}
	grpcSrv := grpc.NewServer()
	grpcService := server.NewGRPCService(shield)
	grpcService.RegisterWith(grpcSrv)

	go func() {
		log.Printf("gRPC server listening on %s", grpcAddr)
		if err := grpcSrv.Serve(lis); err != nil {
			log.Fatalf("gRPC: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("Shutting down...")
	grpcSrv.GracefulStop()
	httpSrv.Shutdown(context.Background())
	log.Println("Server stopped.")
}
