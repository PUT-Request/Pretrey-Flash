package handlers

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/user/pretrey-flash-go/internal/auth"
	"github.com/user/pretrey-flash-go/internal/config"
	"github.com/user/pretrey-flash-go/internal/logger"
)

type AuthHandler struct {
	Auth   *auth.Auth
	Config *config.Config
}

func NewAuthHandler(a *auth.Auth, cfg *config.Config) *AuthHandler {
	return &AuthHandler{Auth: a, Config: cfg}
}

func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := getClientIP(r)
	if h.hasTooManyLoginAttempts(clientIP) {
		jsonError(w, "Too many login attempts. Please try again later.", http.StatusTooManyRequests)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		jsonError(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	if !h.Auth.VerifyCredentials(req.Username, req.Password) {
		h.recordFailedLogin(clientIP)
		jsonError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	h.clearLoginAttempts(clientIP)

	token, err := h.Auth.CreateAuthToken()
	if err != nil {
		logger.LogError("Error creating auth token", err)
		jsonError(w, "Login failed", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "admin_token",
		Value:    token,
		Path:     "/",
		MaxAge:   24 * 60 * 60,
		HttpOnly: true,
		Secure:   h.Auth.IsProduction,
		SameSite: http.SameSiteLaxMode,
	})

	jsonResponse(w, map[string]interface{}{
		"success": true,
		"message": "Login successful",
	})
}

func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "admin_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.Auth.IsProduction,
		SameSite: http.SameSiteLaxMode,
	})

	jsonResponse(w, map[string]interface{}{
		"success": true,
		"message": "Logout successful",
	})
}

// --- Login rate limiting ---

var (
	loginAttempts   = make(map[string]*loginEntry)
	loginMu         sync.Mutex
	lastLoginPrune  time.Time
)

type loginEntry struct {
	Count   int
	ResetAt time.Time
}

func (h *AuthHandler) hasTooManyLoginAttempts(ip string) bool {
	loginMu.Lock()
	defer loginMu.Unlock()

	// Periodic cleanup of expired entries
	now := time.Now()
	if now.Sub(lastLoginPrune) > 5*time.Minute {
		for k, v := range loginAttempts {
			if now.After(v.ResetAt) {
				delete(loginAttempts, k)
			}
		}
		lastLoginPrune = now
	}

	entry, exists := loginAttempts[ip]
	if !exists || now.After(entry.ResetAt) {
		return false
	}
	return entry.Count >= h.Config.RateLimit.MaxLoginAttempts
}

func (h *AuthHandler) recordFailedLogin(ip string) {
	loginMu.Lock()
	defer loginMu.Unlock()

	now := time.Now()
	entry, exists := loginAttempts[ip]
	if !exists || now.After(entry.ResetAt) {
		loginAttempts[ip] = &loginEntry{Count: 1, ResetAt: now.Add(time.Duration(h.Config.RateLimit.LoginWindowSeconds) * time.Second)}
		return
	}
	entry.Count++
}

func (h *AuthHandler) clearLoginAttempts(ip string) {
	loginMu.Lock()
	defer loginMu.Unlock()
	delete(loginAttempts, ip)
}
