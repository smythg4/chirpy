package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeAndValidateJWT(t *testing.T) {
	userID := uuid.New()

	secret := "test-secret-key"

	tests := []struct {
		name           string
		userID         uuid.UUID
		secret         string
		expiresIn      time.Duration
		validateSecret string
		wantErr        bool
	}{
		{
			name:           "Valid token",
			userID:         userID,
			secret:         secret,
			expiresIn:      time.Hour,
			validateSecret: secret,
			wantErr:        false,
		},
		{
			name:           "Expired token",
			userID:         userID,
			secret:         secret,
			expiresIn:      -time.Hour,
			validateSecret: secret,
			wantErr:        true,
		},
		{
			name:           "Wrong secret",
			userID:         userID,
			secret:         secret,
			expiresIn:      time.Hour,
			validateSecret: "wrong-secret",
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := MakeJWT(tt.userID, tt.secret, tt.expiresIn)
			if err != nil {
				t.Fatalf("MakeJWT() error = %v", err)
			}

			gotID, err := ValidateJWT(token, tt.validateSecret)

			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateJWT() error = %v, wantErr = %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && gotID != tt.userID {
				t.Errorf("ValidateJWT() gotID = %v, want %v", gotID, tt.userID)
			}
		})
	}
}
