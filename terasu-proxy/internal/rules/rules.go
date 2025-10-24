package rules

import (
    "net"
    "strings"
)

type Mode string

const (
    ModeAll  Mode = "all"
    ModeList Mode = "list"
)

type Engine struct {
    Mode    Mode
    Suffix  []string
}

func New(mode string, list []string) *Engine {
    e := &Engine{Mode: Mode(mode)}
    for _, d := range list {
        s := strings.ToLower(strings.TrimSpace(d))
        if s == "" {
            continue
        }
        e.Suffix = append(e.Suffix, s)
    }
    return e
}

// ShouldIntercept decides whether a host:port should be MITM-ed.
func (e *Engine) ShouldIntercept(hostport string) bool {
    host, _, err := net.SplitHostPort(hostport)
    if err != nil {
        host = hostport
    }
    host = strings.ToLower(host)
    switch e.Mode {
    case ModeAll:
        return true
    case ModeList:
        for _, suf := range e.Suffix {
            if host == suf || strings.HasSuffix(host, "."+suf) {
                return true
            }
        }
        return false
    default:
        return false
    }
}


