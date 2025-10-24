package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type BasicAuth struct {
	Enabled  bool   `yaml:"enabled"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Security struct {
	BasicAuth BasicAuth `yaml:"basic_auth"`
}

type Limits struct {
	MaxConns     int           `yaml:"max_conns"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

type CA struct {
	CertFile     string `yaml:"cert_file"`
	KeyFile      string `yaml:"key_file"`
	AutoGenerate bool   `yaml:"auto_generate"`
}

type Logging struct {
	Level string `yaml:"level"`
}

type Metrics struct {
	Addr string `yaml:"addr"`
}

type DNS struct {
	Mode string `yaml:"mode"` // terasu | system | auto
}

type Config struct {
	Listen        string   `yaml:"listen"`
	Mode          string   `yaml:"mode"`
	InterceptList []string `yaml:"intercept_list"`
	CA            CA       `yaml:"ca"`
	Security      Security `yaml:"security"`
	Limits        Limits   `yaml:"limits"`
	Logging       Logging  `yaml:"logging"`
	Metrics       Metrics  `yaml:"metrics"`
	DNS           DNS      `yaml:"dns"`
}

func defaultConfig() *Config {
	return &Config{
		Listen:  "0.0.0.0:8080",
		Mode:    "all",
		Limits:  Limits{MaxConns: 4096, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second},
		Logging: Logging{Level: "info"},
		DNS:     DNS{Mode: "auto"},
	}
}

// Load loads config from yaml file; empty path loads defaults only.
func Load(path string) (*Config, error) {
	cfg := defaultConfig()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(b, cfg); err != nil {
			return nil, fmt.Errorf("parse yaml: %w", err)
		}
	}
	// env override
	if v := os.Getenv("TERASU_PROXY_LISTEN"); v != "" {
		cfg.Listen = v
	}
	if v := os.Getenv("TERASU_PROXY_MODE"); v != "" {
		cfg.Mode = v
	}
	if v := os.Getenv("TERASU_PROXY_INTERCEPT_LIST"); v != "" {
		parts := strings.Split(v, ",")
		var list []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				list = append(list, p)
			}
		}
		if len(list) > 0 {
			cfg.InterceptList = list
		}
	}
	if v := os.Getenv("TERASU_PROXY_CA_CERT_FILE"); v != "" {
		cfg.CA.CertFile = v
	}
	if v := os.Getenv("TERASU_PROXY_CA_KEY_FILE"); v != "" {
		cfg.CA.KeyFile = v
	}
	if v := os.Getenv("TERASU_PROXY_CA_AUTO_GENERATE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.CA.AutoGenerate = b
		}
	}
	if v := os.Getenv("TERASU_PROXY_LOG_LEVEL"); v != "" {
		cfg.Logging.Level = v
	}
	if v := os.Getenv("TERASU_PROXY_METRICS_ADDR"); v != "" {
		cfg.Metrics.Addr = v
	}
	if v := os.Getenv("TERASU_PROXY_DNS_MODE"); v != "" {
		cfg.DNS.Mode = v
	}
	if v := os.Getenv("TERASU_PROXY_LIMITS_MAX_CONNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Limits.MaxConns = n
		}
	}
	if v := os.Getenv("TERASU_PROXY_LIMITS_READ_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Limits.ReadTimeout = d
		}
	}
	if v := os.Getenv("TERASU_PROXY_LIMITS_WRITE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Limits.WriteTimeout = d
		}
	}
	if v := os.Getenv("TERASU_PROXY_BASIC_AUTH_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Security.BasicAuth.Enabled = b
		}
	}
	if v := os.Getenv("TERASU_PROXY_BASIC_AUTH_USERNAME"); v != "" {
		cfg.Security.BasicAuth.Username = v
	}
	if v := os.Getenv("TERASU_PROXY_BASIC_AUTH_PASSWORD"); v != "" {
		cfg.Security.BasicAuth.Password = v
	}
	return cfg, nil
}
