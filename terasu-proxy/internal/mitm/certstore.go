package mitm

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "math/big"
    "sync"
    "time"
)

type CertStore struct {
    ca   *CA
    mu   sync.Mutex
    cache map[string]*tls.Certificate
}

func NewCertStore(ca *CA) *CertStore {
    return &CertStore{ca: ca, cache: make(map[string]*tls.Certificate)}
}

func (s *CertStore) GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
    host := chi.ServerName
    if host == "" { host = "unknown" }
    s.mu.Lock()
    if crt, ok := s.cache[host]; ok {
        s.mu.Unlock()
        return crt, nil
    }
    s.mu.Unlock()
    crt, err := s.signLeaf(host)
    if err != nil { return nil, err }
    s.mu.Lock()
    s.cache[host] = crt
    s.mu.Unlock()
    return crt, nil
}

func (s *CertStore) signLeaf(host string) (*tls.Certificate, error) {
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil { return nil, err }
    tmpl := &x509.Certificate{
        SerialNumber: big.NewInt(time.Now().UnixNano()),
        Subject: pkix.Name{CommonName: host},
        DNSNames: []string{host},
        NotBefore: time.Now().Add(-time.Hour),
        NotAfter:  time.Now().AddDate(2,0,0),
        KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
    }
    der, err := x509.CreateCertificate(rand.Reader, tmpl, s.ca.Cert, &key.PublicKey, s.ca.Key)
    if err != nil { return nil, err }
    cert := &tls.Certificate{Certificate: [][]byte{der, s.ca.Cert.Raw}, PrivateKey: key}
    return cert, nil
}


