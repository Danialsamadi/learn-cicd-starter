package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		want       string
		wantErr    bool
		errMessage string
	}{
		{
			name:       "no auth header",
			headers:    http.Header{},
			want:       "",
			wantErr:    true,
			errMessage: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name: "malformed auth header - wrong format",
			headers: http.Header{
				"Authorization": []string{"Bearer token"},
			},
			want:       "",
			wantErr:    true,
			errMessage: "malformed authorization header",
		},
		{
			name: "malformed auth header - missing key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			want:       "",
			wantErr:    true,
			errMessage: "malformed authorization header",
		},
		{
			name: "valid auth header",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-token"},
			},
			want:    "my-secret-token",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err.Error() != tt.errMessage {
				t.Errorf("GetAPIKey() error message = %v, want %v", err.Error(), tt.errMessage)
			}
			if got != tt.want {
				t.Errorf("GetAPIKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
