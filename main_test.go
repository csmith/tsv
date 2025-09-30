package main

import (
	"reflect"
	"testing"
)

func TestParseDomains(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "single domain",
			input: "example.com",
			want:  []string{"example.com"},
		},
		{
			name:  "multiple domains",
			input: "example.com,google.com,github.com",
			want:  []string{"example.com", "google.com", "github.com"},
		},
		{
			name:  "domains with spaces",
			input: "example.com, google.com, github.com",
			want:  []string{"example.com", "google.com", "github.com"},
		},
		{
			name:  "domains with extra spaces",
			input: "  example.com  ,  google.com  ,  github.com  ",
			want:  []string{"example.com", "google.com", "github.com"},
		},
		{
			name:  "empty string",
			input: "",
			want:  []string{},
		},
		{
			name:  "only commas",
			input: ",,,",
			want:  []string{},
		},
		{
			name:  "empty entries between commas",
			input: "example.com,,google.com",
			want:  []string{"example.com", "google.com"},
		},
		{
			name:  "trailing comma",
			input: "example.com,google.com,",
			want:  []string{"example.com", "google.com"},
		},
		{
			name:  "leading comma",
			input: ",example.com,google.com",
			want:  []string{"example.com", "google.com"},
		},
		{
			name:  "mixed whitespace and empty entries",
			input: "example.com,  , google.com,   ,github.com",
			want:  []string{"example.com", "google.com", "github.com"},
		},
		{
			name:  "subdomain",
			input: "api.example.com,www.example.com",
			want:  []string{"api.example.com", "www.example.com"},
		},
		{
			name:  "new-line delimited",
			input: "api.example.com\nwww.example.com",
			want:  []string{"api.example.com", "www.example.com"},
		},
		{
			name:  "whitespace delimited",
			input: "api.example.com\twww.example.com    www.example.net",
			want:  []string{"api.example.com", "www.example.com", "www.example.net"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDomains(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseDomains() = %v, want %v", got, tt.want)
			}
		})
	}
}
