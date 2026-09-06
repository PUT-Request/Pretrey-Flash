package handlers

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/user/pretrey-flash-go/internal/auth"
	"github.com/user/pretrey-flash-go/internal/config"
	"github.com/user/pretrey-flash-go/internal/database"
	"github.com/user/pretrey-flash-go/internal/hashcash"
	"github.com/user/pretrey-flash-go/internal/logger"
	"golang.org/x/crypto/bcrypt"
)

type PagesHandler struct {
	DB     *database.DB
	Auth   *auth.Auth
	Config *config.Config
}

func NewPagesHandler(db *database.DB, a *auth.Auth, cfg *config.Config) *PagesHandler {
	return &PagesHandler{DB: db, Auth: a, Config: cfg}
}

func (h *PagesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Extract slug from path: /api/pages/{slug}
	path := strings.TrimPrefix(r.URL.Path, "/api/pages")
	path = strings.TrimPrefix(path, "/")
	slug := path

	switch r.Method {
	case http.MethodPost:
		h.handleCreate(w, r)
	case http.MethodGet:
		if slug != "" {
			h.handleGet(w, r, slug)
		} else {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		}
	case http.MethodPut:
		if slug != "" {
			h.handleUpdate(w, r, slug)
		} else {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		}
	case http.MethodDelete:
		if slug != "" {
			h.handleDelete(w, r, slug)
		} else {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		}
	default:
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (h *PagesHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	// Rate limit check
	clientIP := getClientIP(r)
	if h.isIPRateLimited(clientIP) {
		jsonError(w, "Too many create attempts. Please wait a minute and try again.", http.StatusTooManyRequests)
		return
	}

	// Body size check
	if r.ContentLength > int64(h.Config.Page.MaxBodyBytes) {
		jsonError(w, "Request body too large (max 512 KB)", http.StatusRequestEntityTooLarge)
		return
	}

	var req struct {
		Title      *string `json:"title"`
		Content    string  `json:"content"`
		Password   *string `json:"password"`
		CustomSlug *string `json:"customSlug"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		jsonError(w, "Content is required", http.StatusBadRequest)
		return
	}

	if len(req.Content) > h.Config.Page.MaxLength {
		jsonError(w, fmt.Sprintf("Content is too large (max %d characters)", h.Config.Page.MaxLength), http.StatusRequestEntityTooLarge)
		return
	}

	if req.Title != nil && len(*req.Title) > h.Config.Page.MaxTitleLength {
		jsonError(w, fmt.Sprintf("Title is too long (max %d characters)", h.Config.Page.MaxTitleLength), http.StatusBadRequest)
		return
	}

	// Validate password
	if req.Password != nil {
		if pwErr := validatePagePassword(*req.Password, h.Config.Page.MaxPasswordLength); pwErr != "" {
			jsonError(w, pwErr, http.StatusBadRequest)
			return
		}
	}

	// Hashcash verification
	hashcashNonce := r.Header.Get("X-Hashcash")
	if hashcashNonce == "" {
		jsonError(w, "Missing spam protection (Hashcash)", http.StatusBadRequest)
		return
	}

	if !hashcash.ValidateNoncePattern(hashcashNonce) {
		jsonError(w, "Invalid spam protection token format", http.StatusBadRequest)
		return
	}

	hashcashTimestampHeader := r.Header.Get("X-Hashcash-Timestamp")
	if hashcashTimestampHeader == "" {
		jsonError(w, "Missing spam protection timestamp", http.StatusBadRequest)
		return
	}

	hashcashTimestamp, err := strconv.ParseInt(hashcashTimestampHeader, 10, 64)
	if err != nil {
		jsonError(w, "Invalid spam protection timestamp", http.StatusBadRequest)
		return
	}

	if time.Duration(abs64(time.Now().UnixMilli()-hashcashTimestamp))*time.Millisecond > hashcash.HashcashTimestampTTL() {
		jsonError(w, "Spam protection challenge expired. Please retry.", http.StatusBadRequest)
		return
	}

	challenge := fmt.Sprintf("pretreyflash:%d", hashcashTimestamp)
	requiredDifficulty := h.Config.Hashcash.DefaultDifficulty
	if req.CustomSlug != nil && *req.CustomSlug != "" {
		requiredDifficulty = h.Config.Hashcash.CustomSlugDifficulty
	}

	replayKey := hashcash.FormatReplayKey(clientIP, challenge, hashcashNonce)
	if hashcash.IsReplay(replayKey) {
		jsonError(w, "Duplicate spam protection token detected. Please retry.", http.StatusConflict)
		return
	}

	if !hashcash.VerifyHashcashServer(challenge, hashcashNonce, requiredDifficulty) {
		if req.CustomSlug != nil && *req.CustomSlug != "" {
			jsonError(w, hashcash.GenerateDifficultyError(h.Config.Hashcash.CustomSlugDifficulty), http.StatusBadRequest)
		} else {
			jsonError(w, "Invalid spam protection", http.StatusBadRequest)
		}
		return
	}

	hashcash.MarkReplayUsed(replayKey, hashcash.HashcashReplayTTL())

	// Generate or validate slug
	var slug string
	if req.CustomSlug != nil && *req.CustomSlug != "" {
		slug = strings.ToLower(strings.TrimSpace(*req.CustomSlug))
		if !matchesPattern(slug, h.Config.Page.CustomSlugPattern) {
			jsonError(w, "Custom URL must be 3-64 chars and use lowercase letters, numbers, hyphens, or underscores", http.StatusBadRequest)
			return
		}
		existing, _ := h.DB.GetPageBySlug(slug)
		if existing != nil {
			jsonError(w, "Custom URL is already taken", http.StatusConflict)
			return
		}
	} else {
		slug = generateSlug(10)
		for attempts := 0; attempts < 5; attempts++ {
			existing, _ := h.DB.GetPageBySlug(slug)
			if existing == nil {
				break
			}
			slug = generateSlug(10)
		}
	}

	// Hash password
	var hashedPassword *string
	if req.Password != nil && *req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), 10)
		if err != nil {
			jsonError(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}
		hashed := string(hash)
		hashedPassword = &hashed
	}

	editCode := generateEditCode()
	pageID := generateSlug(24)
	now := time.Now()

	page := &database.Page{
		ID:           pageID,
		Slug:         slug,
		Title:        req.Title,
		Content:      req.Content,
		Password:     hashedPassword,
		PasswordPlain: req.Password,
		EditCode:     editCode,
		IsPublic:     req.Password == nil || *req.Password == "",
		CreatedAt:    now,
		UpdatedAt:    now,
		ViewCount:    0,
	}

	if err := h.DB.CreatePage(page); err != nil {
		logger.LogError("Error creating page", err)
		jsonError(w, "Failed to create page", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"success":  true,
		"slug":     page.Slug,
		"editCode": page.EditCode,
		"url":      "/p/" + page.Slug,
	})
}

func (h *PagesHandler) handleGet(w http.ResponseWriter, r *http.Request, slug string) {
	password := r.URL.Query().Get("password")

	page, err := h.DB.GetPageBySlug(slug)
	if err != nil {
		jsonError(w, "Page not found", http.StatusNotFound)
		return
	}

	// Check password
	if page.Password != nil {
		if password == "" {
			jsonError(w, "Password required", http.StatusUnauthorized)
			return
		}

		clientIP := getClientIP(r)
		if h.isPasswordRateLimited(clientIP) {
			jsonError(w, "Too many password attempts. Please try again later.", http.StatusTooManyRequests)
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(*page.Password), []byte(password)); err != nil {
			jsonError(w, "Invalid password", http.StatusUnauthorized)
			return
		}

		h.clearPasswordRateLimit(clientIP)
	}

	// Increment view count
	h.DB.IncrementViewCount(slug)
	page.ViewCount++

	jsonResponse(w, page)
}

func (h *PagesHandler) handleUpdate(w http.ResponseWriter, r *http.Request, slug string) {
	var req struct {
		Content  string `json:"content"`
		EditCode string `json:"editCode"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.EditCode == "" {
		jsonError(w, "Edit code is required", http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		jsonError(w, "Content is required", http.StatusBadRequest)
		return
	}

	if len(req.Content) > h.Config.Page.MaxLength {
		jsonError(w, fmt.Sprintf("Content is too large (max %d characters)", h.Config.Page.MaxLength), http.StatusRequestEntityTooLarge)
		return
	}

	// Hashcash verification
	hashcashNonce := r.Header.Get("X-Hashcash")
	if hashcashNonce == "" {
		jsonError(w, "Missing spam protection (Hashcash)", http.StatusBadRequest)
		return
	}
	if !hashcash.VerifyHashcashServer("pretreyflash", hashcashNonce, h.Config.Hashcash.DefaultDifficulty) {
		jsonError(w, "Invalid spam protection", http.StatusBadRequest)
		return
	}

	page, err := h.DB.GetPageBySlug(slug)
	if err != nil {
		jsonError(w, "Page not found", http.StatusNotFound)
		return
	}

	if page.EditCode != req.EditCode {
		jsonError(w, "Invalid edit code", http.StatusForbidden)
		return
	}

	if err := h.DB.UpdatePageContent(slug, req.Content); err != nil {
		logger.LogError("Error updating page", err)
		jsonError(w, "Failed to update page", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"success": true,
		"slug":    slug,
		"url":     "/p/" + slug,
	})
}

func (h *PagesHandler) handleDelete(w http.ResponseWriter, r *http.Request, slug string) {
	var req struct {
		EditCode string `json:"editCode"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.EditCode == "" {
		jsonError(w, "Edit code is required", http.StatusBadRequest)
		return
	}

	hashcashNonce := r.Header.Get("X-Hashcash")
	if hashcashNonce == "" {
		jsonError(w, "Missing spam protection (Hashcash)", http.StatusBadRequest)
		return
	}
	if !hashcash.VerifyHashcashServer("pretreyflash", hashcashNonce, h.Config.Hashcash.DefaultDifficulty) {
		jsonError(w, "Invalid spam protection", http.StatusBadRequest)
		return
	}

	page, err := h.DB.GetPageBySlug(slug)
	if err != nil {
		jsonError(w, "Page not found", http.StatusNotFound)
		return
	}

	if page.EditCode != req.EditCode {
		jsonError(w, "Invalid edit code", http.StatusForbidden)
		return
	}

	if err := h.DB.DeletePage(page.ID); err != nil {
		logger.LogError("Error deleting page", err)
		jsonError(w, "Failed to delete page", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"success": true,
		"message": "Page deleted",
	})
}

// --- Rate limiting ---

var ipRequestWindows = make(map[string]*ipWindow)

type ipWindow struct {
	Count       int
	WindowStart time.Time
}

func (h *PagesHandler) isIPRateLimited(ip string) bool {
	now := time.Now()
	current, exists := ipRequestWindows[ip]
	if !exists || now.Sub(current.WindowStart) > time.Duration(h.Config.RateLimit.WindowSeconds)*time.Second {
		ipRequestWindows[ip] = &ipWindow{Count: 1, WindowStart: now}
		return false
	}
	if current.Count >= h.Config.RateLimit.MaxCreatePerIP {
		return true
	}
	current.Count++
	return false
}

var passwordAttempts = make(map[string]*rateEntry)

type rateEntry struct {
	Count   int
	ResetAt time.Time
}

func (h *PagesHandler) isPasswordRateLimited(ip string) bool {
	now := time.Now()
	entry, exists := passwordAttempts[ip]
	if !exists || now.After(entry.ResetAt) {
		passwordAttempts[ip] = &rateEntry{Count: 1, ResetAt: now.Add(time.Duration(h.Config.RateLimit.PasswordWindowSeconds) * time.Second)}
		return false
	}
	if entry.Count >= h.Config.RateLimit.MaxPasswordAttempts {
		return true
	}
	entry.Count++
	return false
}

func (h *PagesHandler) clearPasswordRateLimit(ip string) {
	delete(passwordAttempts, ip)
}

// --- Helpers ---

func getClientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return strings.TrimSpace(realIP)
	}
	return "unknown"
}

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func generateSlug(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b[i] = chars[num.Int64()]
	}
	return string(b)
}

func generateEditCode() string {
	return generateSlug(24)
}

func matchesPattern(s, pattern string) bool {
	// Simple regex match for ^[a-z0-9_-]{3,64}$
	if len(s) < 3 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func abs64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

func validatePagePassword(password string, maxLen int) string {
	if password == "" {
		return ""
	}
	if len(password) > maxLen {
		return fmt.Sprintf("Password is too long (max %d characters)", maxLen)
	}
	for _, c := range password {
		if c < 0x20 || c > 0x7E {
			return "Password contains unsupported characters"
		}
	}
	return ""
}
