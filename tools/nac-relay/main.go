// nac-relay: Runs on a Mac and serves NAC validation data over HTTPS with
// bearer-token auth. The Linux bridge calls this instead of running the
// x86_64 NAC emulator locally.
//
// On first run, a self-signed TLS certificate and random bearer token are
// generated and stored in ~/Library/Application Support/nac-relay/.
// extract-key reads relay-info.json from the same directory and embeds
// the token + cert fingerprint into the hardware key.
//
// Usage:
//   go run tools/nac-relay/main.go [-port 5001] [-addr 0.0.0.0]
//
// Endpoints (all require Authorization: Bearer <token> except /health):
//   POST /validation-data       → base64-encoded validation data (single-shot)
//   POST /nac/init              → {session_id, request_bytes} (step 1)
//   POST /nac/key_establishment → {ok} (step 2, client posts Apple's session_info)
//   POST /nac/sign              → {validation_data} (step 3, final bytes)
//   GET  /health                → "ok" (no auth required)
//
// The 3-step API mirrors AAAbsintheContext's NACInit / NACKeyEstablishment /
// NACSign so the Linux bridge (via open-absinthe's ValidationCtx Relay
// variant) can drive the Apple `id-initialize-validation` POST itself and
// plumb the response back to the relay for key establishment + signing.
// This is the path Apple Silicon hardware keys take since they can't run
// in the bridge's local unicorn x86-64 emulator.
package main

/*
#cgo CFLAGS: -x objective-c -DNAC_NO_MAIN -fobjc-arc
#cgo LDFLAGS: -framework Foundation

// Inline the validation_data.m source
#include "../../nac-validation/src/validation_data.m"
*/
import "C"

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

var nacMu sync.Mutex // serialize NAC calls (framework may not be thread-safe)

func generateValidationData() ([]byte, error) {
	nacMu.Lock()
	defer nacMu.Unlock()

	var buf *C.uint8_t
	var bufLen C.size_t
	var errBuf *C.char

	result := C.nac_generate_validation_data(&buf, &bufLen, &errBuf)
	if result != 0 {
		errMsg := "unknown error"
		if errBuf != nil {
			errMsg = C.GoString(errBuf)
			C.free(unsafe.Pointer(errBuf))
		}
		return nil, fmt.Errorf("NAC error %d: %s", result, errMsg)
	}

	data := C.GoBytes(unsafe.Pointer(buf), C.int(bufLen))
	C.free(unsafe.Pointer(buf))
	return data, nil
}

// ---- 3-step NAC session store ----
//
// The 3-step protocol holds an opaque AAAbsintheContext handle between
// HTTP calls. We park it here keyed by a random session_id, with a TTL
// that's generous enough for the client's Apple round-trip but short
// enough to avoid leaks.

type nacSession struct {
	handle    unsafe.Pointer // NacContext* from nac_ctx_init
	createdAt time.Time
}

var (
	sessionsMu sync.Mutex
	sessions   = map[string]*nacSession{}
)

const sessionTTL = 2 * time.Minute

func newSessionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func saveSession(handle unsafe.Pointer) (string, error) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	// Opportunistic GC of expired sessions.
	now := time.Now()
	for id, s := range sessions {
		if now.Sub(s.createdAt) > sessionTTL {
			C.nac_ctx_free(s.handle)
			delete(sessions, id)
		}
	}
	id, err := newSessionID()
	if err != nil {
		return "", err
	}
	sessions[id] = &nacSession{handle: handle, createdAt: now}
	return id, nil
}

func loadSession(id string) (*nacSession, error) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	s, ok := sessions[id]
	if !ok {
		return nil, errors.New("unknown session_id")
	}
	if time.Since(s.createdAt) > sessionTTL {
		C.nac_ctx_free(s.handle)
		delete(sessions, id)
		return nil, errors.New("session expired")
	}
	return s, nil
}

func dropSession(id string) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	if s, ok := sessions[id]; ok {
		C.nac_ctx_free(s.handle)
		delete(sessions, id)
	}
}

// nacCtxInit wraps the 3-step nac_ctx_init C entry point.
// Returns (opaque ctx handle, request bytes, error).
func nacCtxInit(cert []byte) (unsafe.Pointer, []byte, error) {
	nacMu.Lock()
	defer nacMu.Unlock()

	var handle unsafe.Pointer
	var reqBuf *C.uint8_t
	var reqLen C.size_t
	var errBuf *C.char

	certPtr := (*C.uint8_t)(nil)
	if len(cert) > 0 {
		certPtr = (*C.uint8_t)(unsafe.Pointer(&cert[0]))
	}
	result := C.nac_ctx_init(certPtr, C.size_t(len(cert)), &handle, &reqBuf, &reqLen, &errBuf)
	if result != 0 {
		msg := "nac_ctx_init failed"
		if errBuf != nil {
			msg = C.GoString(errBuf)
			C.free(unsafe.Pointer(errBuf))
		}
		return nil, nil, fmt.Errorf("nac_ctx_init code %d: %s", result, msg)
	}
	req := C.GoBytes(unsafe.Pointer(reqBuf), C.int(reqLen))
	C.free(unsafe.Pointer(reqBuf))
	return handle, req, nil
}

// nacCtxKeyEstablishment wraps nac_ctx_key_establishment.
func nacCtxKeyEstablishment(handle unsafe.Pointer, sessionInfo []byte) error {
	nacMu.Lock()
	defer nacMu.Unlock()

	var errBuf *C.char
	siPtr := (*C.uint8_t)(nil)
	if len(sessionInfo) > 0 {
		siPtr = (*C.uint8_t)(unsafe.Pointer(&sessionInfo[0]))
	}
	result := C.nac_ctx_key_establishment(handle, siPtr, C.size_t(len(sessionInfo)), &errBuf)
	if result != 0 {
		msg := "nac_ctx_key_establishment failed"
		if errBuf != nil {
			msg = C.GoString(errBuf)
			C.free(unsafe.Pointer(errBuf))
		}
		return fmt.Errorf("nac_ctx_key_establishment code %d: %s", result, msg)
	}
	return nil
}

// nacCtxSign wraps nac_ctx_sign.
func nacCtxSign(handle unsafe.Pointer) ([]byte, error) {
	nacMu.Lock()
	defer nacMu.Unlock()

	var outBuf *C.uint8_t
	var outLen C.size_t
	var errBuf *C.char
	result := C.nac_ctx_sign(handle, &outBuf, &outLen, &errBuf)
	if result != 0 {
		msg := "nac_ctx_sign failed"
		if errBuf != nil {
			msg = C.GoString(errBuf)
			C.free(unsafe.Pointer(errBuf))
		}
		return nil, fmt.Errorf("nac_ctx_sign code %d: %s", result, msg)
	}
	data := C.GoBytes(unsafe.Pointer(outBuf), C.int(outLen))
	C.free(unsafe.Pointer(outBuf))
	return data, nil
}

// ---- 3-step HTTP handlers ----

type initReq struct {
	Cert string `json:"cert"` // base64
}
type initResp struct {
	SessionID    string `json:"session_id"`
	RequestBytes string `json:"request_bytes"` // base64
}

func handleNacInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("read body: %v", err), http.StatusBadRequest)
		return
	}
	var req initReq
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("json: %v", err), http.StatusBadRequest)
		return
	}
	cert, err := base64.StdEncoding.DecodeString(req.Cert)
	if err != nil {
		http.Error(w, fmt.Sprintf("cert base64: %v", err), http.StatusBadRequest)
		return
	}
	handle, reqBytes, err := nacCtxInit(cert)
	if err != nil {
		log.Printf("ERROR nac_ctx_init: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sid, err := saveSession(handle)
	if err != nil {
		C.nac_ctx_free(handle)
		http.Error(w, fmt.Sprintf("save session: %v", err), http.StatusInternalServerError)
		return
	}
	resp := initResp{
		SessionID:    sid,
		RequestBytes: base64.StdEncoding.EncodeToString(reqBytes),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
	log.Printf("Served /nac/init: session_id=%s request_bytes=%d (from %s)", sid, len(reqBytes), r.RemoteAddr)
}

type keyEstReq struct {
	SessionID   string `json:"session_id"`
	SessionInfo string `json:"session_info"` // base64
}
type okResp struct {
	OK bool `json:"ok"`
}

func handleNacKeyEstablishment(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("read body: %v", err), http.StatusBadRequest)
		return
	}
	var req keyEstReq
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("json: %v", err), http.StatusBadRequest)
		return
	}
	si, err := base64.StdEncoding.DecodeString(req.SessionInfo)
	if err != nil {
		http.Error(w, fmt.Sprintf("session_info base64: %v", err), http.StatusBadRequest)
		return
	}
	sess, err := loadSession(req.SessionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err := nacCtxKeyEstablishment(sess.handle, si); err != nil {
		log.Printf("ERROR nac_ctx_key_establishment: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(okResp{OK: true})
	log.Printf("Served /nac/key_establishment: session_id=%s session_info=%d (from %s)", req.SessionID, len(si), r.RemoteAddr)
}

type signReq struct {
	SessionID string `json:"session_id"`
}
type signResp struct {
	ValidationData string `json:"validation_data"` // base64
}

func handleNacSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("read body: %v", err), http.StatusBadRequest)
		return
	}
	var req signReq
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("json: %v", err), http.StatusBadRequest)
		return
	}
	sess, err := loadSession(req.SessionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	data, err := nacCtxSign(sess.handle)
	// Free the session once sign runs — success or failure, the context
	// is single-use per the AAAbsintheContext contract.
	dropSession(req.SessionID)
	if err != nil {
		log.Printf("ERROR nac_ctx_sign: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(signResp{
		ValidationData: base64.StdEncoding.EncodeToString(data),
	})
	log.Printf("Served /nac/sign: session_id=%s validation_data=%d bytes (from %s)", req.SessionID, len(data), r.RemoteAddr)
}

func main() {
	if runtime.GOOS != "darwin" {
		fmt.Fprintln(os.Stderr, "nac-relay must run on macOS")
		os.Exit(1)
	}

	addr := flag.String("addr", "0.0.0.0", "Address to bind to")
	port := flag.Int("port", 5001, "Port to listen on")
	setup := flag.Bool("setup", false, "Install .app bundle and LaunchAgent, then start service")
	flag.Parse()

	if *setup {
		runSetup()
		return
	}

	// Test that NAC works on startup
	log.Println("Testing NAC validation data generation...")
	start := time.Now()
	vd, err := generateValidationData()
	if err != nil {
		log.Fatalf("NAC test failed: %v", err)
	}
	log.Printf("NAC test OK: %d bytes in %v", len(vd), time.Since(start))

	// Single-shot endpoint (back-compat with pre-refactor clients).
	http.HandleFunc("/validation-data", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		start := time.Now()
		data, err := generateValidationData()
		if err != nil {
			log.Printf("ERROR: NAC generation failed: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		b64 := base64.StdEncoding.EncodeToString(data)
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(b64))
		log.Printf("Served %d bytes of validation data in %v (from %s)",
			len(data), time.Since(start), r.RemoteAddr)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	// Set up TLS + bearer token auth
	tlsConfig, token, err := ensureRelayAuth()
	if err != nil {
		log.Fatalf("Failed to initialize TLS/auth: %v", err)
	}

	listenAddr := fmt.Sprintf("%s:%d", *addr, *port)
	log.Printf("NAC relay listening on %s (HTTPS)", listenAddr)

	// Print helpful info
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				log.Printf("  → Bridge relay URL: https://%s:%d/validation-data", ipnet.IP, *port)
			}
		}
	}
	log.Println("Use -relay <url> when running extract-key to embed this URL in the hardware key.")

	server := &http.Server{
		Addr:      listenAddr,
		Handler:   authMiddleware(token, http.DefaultServeMux),
		TLSConfig: tlsConfig,
	}
	log.Fatal(server.ListenAndServeTLS("", ""))
}
