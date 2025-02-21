package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Успешный случай
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key")

	key, err := GetAPIKey(headers)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if key != "my-secret-key" {
		t.Errorf("expected 'my-secret-key', got '%s'", key)
	}

	// Случай: нет заголовка Authorization
	emptyHeaders := http.Header{}

	_, err = GetAPIKey(emptyHeaders)
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}

	// Случай: некорректный заголовок
	badHeaders := http.Header{}
	badHeaders.Set("Authorization", "InvalidHeader")

	_, err = GetAPIKey(badHeaders)
	if err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("expected 'malformed authorization header' error, got %v", err)
	}
}
