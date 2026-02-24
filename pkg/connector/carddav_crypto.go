// mautrix-imessage - A Matrix-iMessage puppeting bridge.
// Copyright (C) 2024 Ludvig Rhodin
//
// AES-256-GCM encryption for per-user CardDAV credentials stored in the DB.
// The encryption key is derived deterministically from the bridge AS token
// and the user login ID via HMAC-SHA256, so no key storage is needed.

package connector

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// DeriveCardDAVKey derives a 32-byte AES-256 key for a specific user login.
// Uses HMAC-SHA256 keyed by the bridge AS token with the user login ID as
// the message. Deterministic — no on-disk key storage needed.
func DeriveCardDAVKey(bridgeASToken, userLoginID string) []byte {
	mac := hmac.New(sha256.New, []byte(bridgeASToken))
	mac.Write([]byte(userLoginID))
	return mac.Sum(nil) // 32 bytes — perfect for AES-256
}

// EncryptCardDAVPassword encrypts a plaintext password with AES-256-GCM.
// Returns base64-encoded ciphertext with the nonce prepended.
func EncryptCardDAVPassword(key []byte, password string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Seal prepends nonce to ciphertext
	ciphertext := gcm.Seal(nonce, nonce, []byte(password), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptCardDAVPassword decrypts a base64-encoded AES-256-GCM ciphertext.
func DecryptCardDAVPassword(key []byte, encrypted string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}
