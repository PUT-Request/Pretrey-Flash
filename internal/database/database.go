package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Page struct {
	ID           string     `json:"id"`
	Slug         string     `json:"slug"`
	Title        *string    `json:"title"`
	Content      string     `json:"content"`
	Password     *string    `json:"password,omitempty"`
	PasswordPlain *string   `json:"passwordPlain,omitempty"`
	EditCode     string     `json:"editCode"`
	IsPublic     bool       `json:"isPublic"`
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    time.Time  `json:"updatedAt"`
	ViewCount    int        `json:"viewCount"`
}

type DB struct {
	conn *sql.DB
}

func New(dbPath string) (*DB, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	conn, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	conn.SetMaxOpenConns(1)

	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return db, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}

func (db *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS pages (
		id TEXT PRIMARY KEY,
		slug TEXT UNIQUE NOT NULL,
		title TEXT,
		content TEXT NOT NULL,
		password TEXT,
		password_plain TEXT,
		edit_code TEXT NOT NULL,
		is_public INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		view_count INTEGER NOT NULL DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_pages_slug ON pages(slug);
	`

	_, err := db.conn.Exec(schema)
	return err
}

func (db *DB) CreatePage(p *Page) error {
	_, err := db.conn.Exec(
		`INSERT INTO pages (id, slug, title, content, password, password_plain, edit_code, is_public, created_at, updated_at, view_count)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Slug, p.Title, p.Content, p.Password, p.PasswordPlain, p.EditCode, boolToInt(p.IsPublic), p.CreatedAt, p.UpdatedAt, p.ViewCount,
	)
	return err
}

func (db *DB) GetPageBySlug(slug string) (*Page, error) {
	row := db.conn.QueryRow(
		`SELECT id, slug, title, content, password, password_plain, edit_code, is_public, created_at, updated_at, view_count
		 FROM pages WHERE slug = ?`, slug,
	)
	return scanPage(row)
}

func (db *DB) GetPageByID(id string) (*Page, error) {
	row := db.conn.QueryRow(
		`SELECT id, slug, title, content, password, password_plain, edit_code, is_public, created_at, updated_at, view_count
		 FROM pages WHERE id = ?`, id,
	)
	return scanPage(row)
}

func (db *DB) UpdatePageContent(slug, content string) error {
	_, err := db.conn.Exec(
		`UPDATE pages SET content = ?, updated_at = ? WHERE slug = ?`,
		content, time.Now(), slug,
	)
	return err
}

func (db *DB) DeletePage(id string) error {
	_, err := db.conn.Exec(`DELETE FROM pages WHERE id = ?`, id)
	return err
}

func (db *DB) IncrementViewCount(slug string) error {
	_, err := db.conn.Exec(
		`UPDATE pages SET view_count = view_count + 1 WHERE slug = ?`, slug,
	)
	return err
}

func (db *DB) ListPages(search string, offset, limit int) ([]Page, int, error) {
	var countQuery, listQuery string
	var args []interface{}

	if search != "" {
		countQuery = `
			SELECT COUNT(*) FROM pages
			WHERE title LIKE ? OR content LIKE ? OR slug LIKE ?
		`
		listQuery = `
			SELECT id, slug, title, content, password, password_plain, edit_code, is_public, created_at, updated_at, view_count
			FROM pages
			WHERE title LIKE ? OR content LIKE ? OR slug LIKE ?
			ORDER BY created_at DESC LIMIT ? OFFSET ?
		`
		likeSearch := "%" + search + "%"
		args = []interface{}{likeSearch, likeSearch, likeSearch}
	} else {
		countQuery = `SELECT COUNT(*) FROM pages`
		listQuery = `
			SELECT id, slug, title, content, password, password_plain, edit_code, is_public, created_at, updated_at, view_count
			FROM pages
			ORDER BY created_at DESC LIMIT ? OFFSET ?
		`
	}

	var total int
	if err := db.conn.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listArgs := append(args, limit, offset)
	rows, err := db.conn.Query(listQuery, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var pages []Page
	for rows.Next() {
		p, err := scanPageRows(rows)
		if err != nil {
			return nil, 0, err
		}
		pages = append(pages, *p)
	}

	return pages, total, nil
}

func (db *DB) CountRecentPages(hours int) (int, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	var count int
	err := db.conn.QueryRow(
		`SELECT COUNT(*) FROM pages WHERE created_at >= ?`, since,
	).Scan(&count)
	return count, err
}

func (db *DB) GetRecentPageCounts(hours int) ([]struct{ Hour string; Count int }, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	rows, err := db.conn.Query(
		`SELECT substr(created_at, 1, 4) || '-' || substr(created_at, 6, 2) || '-' || substr(created_at, 9, 2) || 'T' || substr(created_at, 12, 2) || ':00' as hour, COUNT(*)
		 FROM pages WHERE created_at >= ?
		 GROUP BY hour ORDER BY hour`, since,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []struct {
		Hour  string
		Count int
	}
	for rows.Next() {
		var hour string
		var count int
		if err := rows.Scan(&hour, &count); err != nil {
			return nil, err
		}
		results = append(results, struct {
			Hour  string
			Count int
		}{hour, count})
	}
	return results, nil
}

func scanPage(row *sql.Row) (*Page, error) {
	var p Page
	var isPublic int
	err := row.Scan(&p.ID, &p.Slug, &p.Title, &p.Content, &p.Password, &p.PasswordPlain, &p.EditCode, &isPublic, &p.CreatedAt, &p.UpdatedAt, &p.ViewCount)
	if err != nil {
		return nil, err
	}
	p.IsPublic = isPublic != 0
	return &p, nil
}

func scanPageRows(rows *sql.Rows) (*Page, error) {
	var p Page
	var isPublic int
	err := rows.Scan(&p.ID, &p.Slug, &p.Title, &p.Content, &p.Password, &p.PasswordPlain, &p.EditCode, &isPublic, &p.CreatedAt, &p.UpdatedAt, &p.ViewCount)
	if err != nil {
		return nil, err
	}
	p.IsPublic = isPublic != 0
	return &p, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
