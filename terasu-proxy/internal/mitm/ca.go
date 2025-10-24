package mitm

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "errors"
    "fmt"
    "math/big"
    "os"
    "time"
)

type CA struct {
    Cert *x509.Certificate
    Key  *rsa.PrivateKey
    certPEM []byte
    keyPEM  []byte
}

func LoadOrCreate(certFile, keyFile string, auto bool) (*CA, error) {
    if certFile == "" || keyFile == "" {
        return nil, errors.New("empty ca cert/key path")
    }
    certPEM, certErr := os.ReadFile(certFile)
    keyPEM, keyErr := os.ReadFile(keyFile)
    if certErr == nil && keyErr == nil {
        cert, key, err := parseCA(certPEM, keyPEM)
        if err != nil {
            return nil, err
        }
        return &CA{Cert: cert, Key: key, certPEM: certPEM, keyPEM: keyPEM}, nil
    }
    if !auto {
        return nil, fmt.Errorf("ca not found and auto_generate=false")
    }
    ca, err := generateCA()
    if err != nil {
        return nil, err
    }
    if err := os.MkdirAll(dirOf(certFile), 0o755); err != nil { return nil, err }
    if err := os.WriteFile(certFile, ca.certPEM, 0o600); err != nil { return nil, err }
    if err := os.WriteFile(keyFile, ca.keyPEM, 0o600); err != nil { return nil, err }
    return ca, nil
}

func parseCA(certPEM, keyPEM []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
    cb, _ := pem.Decode(certPEM)
    if cb == nil { return nil, nil, errors.New("invalid cert pem") }
    kb, _ := pem.Decode(keyPEM)
    if kb == nil { return nil, nil, errors.New("invalid key pem") }
    cert, err := x509.ParseCertificate(cb.Bytes)
    if err != nil { return nil, nil, err }
    key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
    if err != nil { return nil, nil, err }
    return cert, key, nil
}

func generateCA() (*CA, error) {
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil { return nil, err }
    tmpl := &x509.Certificate{
        SerialNumber: big.NewInt(time.Now().UnixNano()),
        Subject: pkix.Name{CommonName: "terasu-proxy CA"},
        NotBefore: time.Now().Add(-time.Hour),
        NotAfter:  time.Now().AddDate(10,0,0),
        KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
        BasicConstraintsValid: true,
        IsCA: true,
        MaxPathLen: 1,
    }
    der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
    if err != nil { return nil, err }
    certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
    keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
    cert, _ := x509.ParseCertificate(der)
    return &CA{Cert: cert, Key: key, certPEM: certPEM, keyPEM: keyPEM}, nil
}

func dirOf(path string) string {
    for i := len(path)-1; i >= 0; i-- {
        if path[i] == '/' { return path[:i] }
    }
    return "."
}


