package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Port int    `yaml:"port"`
		Host string `yaml:"host"`
	} `yaml:"server"`

	Database struct {
		Path string `yaml:"path"`
	} `yaml:"database"`

	Admin struct {
		Username    string `yaml:"username"`
		Password    string `yaml:"password"`
		TokenSecret string `yaml:"token_secret"`
	} `yaml:"admin"`

	Hashcash struct {
		DefaultDifficulty  int `yaml:"default_difficulty"`
		CustomSlugDifficulty int `yaml:"custom_slug_difficulty"`
	} `yaml:"hashcash"`

	RateLimit struct {
		MaxCreatePerIP    int `yaml:"max_create_per_ip"`
		WindowSeconds     int `yaml:"window_seconds"`
		MaxPasswordAttempts int `yaml:"max_password_attempts"`
		PasswordWindowSeconds int `yaml:"password_window_seconds"`
		MaxLoginAttempts  int `yaml:"max_login_attempts"`
		LoginWindowSeconds int `yaml:"login_window_seconds"`
	} `yaml:"rate_limit"`

	Page struct {
		MaxLength         int    `yaml:"max_content_length"`
		MaxTitleLength    int    `yaml:"max_title_length"`
		MaxBodyBytes      int    `yaml:"max_body_bytes"`
		MaxPasswordLength int    `yaml:"max_password_length"`
		CustomSlugPattern string `yaml:"custom_slug_pattern"`
	} `yaml:"page"`

	CORS struct {
		AllowedOrigins []string `yaml:"allowed_origins"`
	} `yaml:"cors"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Server: struct {
			Port int    `yaml:"port"`
			Host string `yaml:"host"`
		}{Port: 8080, Host: "0.0.0.0"},
		Database: struct {
			Path string `yaml:"path"`
		}{Path: "./data/pretrey.db"},
		Admin: struct {
			Username    string `yaml:"username"`
			Password    string `yaml:"password"`
			TokenSecret string `yaml:"token_secret"`
		}{Username: "admin", Password: "admin", TokenSecret: "dev-secret"},
		Hashcash: struct {
			DefaultDifficulty    int `yaml:"default_difficulty"`
			CustomSlugDifficulty int `yaml:"custom_slug_difficulty"`
		}{DefaultDifficulty: 12, CustomSlugDifficulty: 18},
		RateLimit: struct {
			MaxCreatePerIP        int `yaml:"max_create_per_ip"`
			WindowSeconds         int `yaml:"window_seconds"`
			MaxPasswordAttempts   int `yaml:"max_password_attempts"`
			PasswordWindowSeconds int `yaml:"password_window_seconds"`
			MaxLoginAttempts      int `yaml:"max_login_attempts"`
			LoginWindowSeconds    int `yaml:"login_window_seconds"`
		}{MaxCreatePerIP: 20, WindowSeconds: 60, MaxPasswordAttempts: 10, PasswordWindowSeconds: 60, MaxLoginAttempts: 10, LoginWindowSeconds: 60},
		Page: struct {
			MaxLength         int    `yaml:"max_content_length"`
			MaxTitleLength    int    `yaml:"max_title_length"`
			MaxBodyBytes      int    `yaml:"max_body_bytes"`
			MaxPasswordLength int    `yaml:"max_password_length"`
			CustomSlugPattern string `yaml:"custom_slug_pattern"`
		}{MaxLength: 200000, MaxTitleLength: 200, MaxBodyBytes: 524288, MaxPasswordLength: 15, CustomSlugPattern: "^[a-z0-9_-]{3,64}$"},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
