package auth

import (
    "net/http"
)

type Basic struct {
    Enabled  bool
    Username string
    Password string
}

func (b Basic) Check(r *http.Request) bool {
    if !b.Enabled { return true }
    u, p, ok := r.BasicAuth()
    if !ok { return false }
    if b.Username == "" && b.Password == "" { return true }
    return u == b.Username && p == b.Password
}


