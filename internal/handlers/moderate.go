package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/user/pretrey-flash-go/internal/auth"
	"github.com/user/pretrey-flash-go/internal/config"
	"github.com/user/pretrey-flash-go/internal/database"
	"github.com/user/pretrey-flash-go/internal/logger"
)

type ModerateHandler struct {
	DB     *database.DB
	Auth   *auth.Auth
	Config *config.Config
}

func NewModerateHandler(db *database.DB, a *auth.Auth, cfg *config.Config) *ModerateHandler {
	return &ModerateHandler{DB: db, Auth: a, Config: cfg}
}

func (h *ModerateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.Auth.IsAuthenticated(r) {
		jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/moderate")
	path = strings.TrimPrefix(path, "/")

	switch {
	case path == "pages" && r.Method == http.MethodGet:
		h.handleListPages(w, r)
	case path == "stats" && r.Method == http.MethodGet:
		h.handleStats(w, r)
	case strings.HasPrefix(path, "pages/") && r.Method == http.MethodDelete:
		id := strings.TrimPrefix(path, "pages/")
		h.handleDeletePage(w, r, id)
	default:
		jsonError(w, "Not found", http.StatusNotFound)
	}
}

func (h *ModerateHandler) handleListPages(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	search := strings.TrimSpace(r.URL.Query().Get("search"))

	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 10
	}

	offset := (page - 1) * limit
	pages, totalCount, err := h.DB.ListPages(search, offset, limit)
	if err != nil {
		logger.LogError("Error listing pages", err)
		jsonError(w, "Failed to fetch pages", http.StatusInternalServerError)
		return
	}

	recentCount, _ := h.DB.CountRecentPages(12)

	jsonResponse(w, map[string]interface{}{
		"pages": pages,
		"pagination": map[string]interface{}{
			"page":       page,
			"limit":      limit,
			"totalCount": totalCount,
			"totalPages": (totalCount + limit - 1) / limit,
		},
		"stats": map[string]interface{}{
			"totalCount":  totalCount,
			"recentCount": recentCount,
		},
	})
}

func (h *ModerateHandler) handleDeletePage(w http.ResponseWriter, r *http.Request, id string) {
	page, err := h.DB.GetPageByID(id)
	if err != nil {
		jsonError(w, "Page not found", http.StatusNotFound)
		return
	}

	if err := h.DB.DeletePage(page.ID); err != nil {
		logger.LogError("Error deleting page", err)
		jsonError(w, "Failed to delete page", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"success": true,
		"message": "Page deleted successfully",
	})
}

func (h *ModerateHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	hourlyData, err := h.DB.GetRecentPageCounts(12)
	if err != nil {
		logger.LogError("Error fetching stats", err)
		jsonError(w, "Failed to fetch statistics", http.StatusInternalServerError)
		return
	}

	totalLast12Hours := 0
	for _, d := range hourlyData {
		totalLast12Hours += d.Count
	}

	// Format for chart display
	type chartPoint struct {
		Hour  string `json:"hour"`
		Count int    `json:"count"`
	}
	var chart []chartPoint
	for _, d := range hourlyData {
		chart = append(chart, chartPoint{
			Hour:  d.Hour,
			Count: d.Count,
		})
	}

	jsonResponse(w, map[string]interface{}{
		"data":              chart,
		"totalLast12Hours":  totalLast12Hours,
	})
}

var _ = json.Marshal
