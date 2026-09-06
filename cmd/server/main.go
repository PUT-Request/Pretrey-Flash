package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/user/pretrey-flash-go/internal/auth"
	"github.com/user/pretrey-flash-go/internal/config"
	"github.com/user/pretrey-flash-go/internal/database"
	"github.com/user/pretrey-flash-go/internal/handlers"
	"github.com/user/pretrey-flash-go/internal/logger"
)

func main() {
	configPath := "config.yaml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if os.Getenv("GO_ENV") == "production" {
		if cfg.Admin.Username == "admin" || cfg.Admin.Password == "admin" {
			log.Fatal("Security Error: Default admin credentials detected in production.")
		}
		if cfg.Admin.TokenSecret == "dev-only-change-me-please-dev-only-change-me" {
			log.Fatal("Security Error: Default token secret detected in production.")
		}
	}

	logger.SetProduction(os.Getenv("GO_ENV") == "production")

	db, err := database.New(cfg.Database.Path)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	a := auth.New(cfg.Admin.Username, cfg.Admin.Password, cfg.Admin.TokenSecret, os.Getenv("GO_ENV") == "production")

	pagesHandler := handlers.NewPagesHandler(db, a, cfg)
	authHandler := handlers.NewAuthHandler(a, cfg)
	moderateHandler := handlers.NewModerateHandler(db, a, cfg)

	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/pages", pagesHandler.ServeHTTP)
	mux.HandleFunc("/api/pages/", pagesHandler.ServeHTTP)
	mux.HandleFunc("/api/auth/login", authHandler.HandleLogin)
	mux.HandleFunc("/api/auth/logout", authHandler.HandleLogout)
	mux.HandleFunc("/api/moderate/", moderateHandler.ServeHTTP)

	// Static file handler with SPA support
	staticDir := "./frontend/out"

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}

		// Sanitize path to prevent path traversal attacks
		// Clean the path and ensure it stays within the static directory
		cleanPath := filepath.Clean(r.URL.Path)
		if cleanPath == "" {
			cleanPath = "/"
		}

		// Reject paths that attempt to traverse outside the static directory
		if strings.Contains(cleanPath, "..") {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}

		fullPath := filepath.Join(staticDir, cleanPath)

		// Double-check the resolved path is within the static directory
		absStaticDir, err := filepath.Abs(staticDir)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		absFullPath, err := filepath.Abs(fullPath)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if !strings.HasPrefix(absFullPath, absStaticDir+string(filepath.Separator)) && absFullPath != absStaticDir {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		// 1. Try exact file
		if info, err := os.Stat(absFullPath); err == nil && !info.IsDir() {
			http.ServeFile(w, r, absFullPath)
			return
		}

		// 2. Try path.html (SPA routes like /new -> /new.html)
		if !strings.HasSuffix(cleanPath, "/") {
			htmlPath := absFullPath + ".html"
			if _, err := os.Stat(htmlPath); err == nil {
				http.ServeFile(w, r, htmlPath)
				return
			}
		}

		// 3. Try path/index.html
		indexPath := absFullPath + "/index.html"
		if _, err := os.Stat(indexPath); err == nil {
			http.ServeFile(w, r, indexPath)
			return
		}

		// 4. SPA fallback
		http.ServeFile(w, r, absStaticDir+"/index.html")
	})

	handler := corsMiddleware(mux, cfg)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	log.Printf("Server starting on %s", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func corsMiddleware(next http.Handler, cfg *config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowed := false
		for _, o := range cfg.CORS.AllowedOrigins {
			if o == "*" || o == origin {
				allowed = true
				break
			}
		}
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Hashcash, X-Hashcash-Timestamp")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
