package wipeme

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const (
	testID   = "1K7mQ2xR8VpC"
	testHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testKey  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	client, err := NewClient(ClientOptions{BaseURL: server.URL, ClientID: "mobile-ios"})
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	return client, server
}

func TestCreateSendsBinaryEnvelopeAndHeaders(t *testing.T) {
	envelope := []byte{0, 1, 2, 0xff}
	envelopeHash := fmt.Sprintf("%x", sha256.Sum256(envelope))
	client, server := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/messages/"+testID {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if !bytes.Equal(body, envelope) {
			t.Errorf("body = %v", body)
		}
		wantHeaders := map[string]string{
			"Content-Type": "application/octet-stream", "X-Wipe-Content-Hash": envelopeHash,
			"X-Wipe-Deletion-Key": testKey, "X-Wipe-Cipher-Version": "1",
			"X-Wipe-Expires-At": "1800086400000", "X-Wipe-Client": "mobile-ios",
		}
		for name, want := range wantHeaders {
			if got := r.Header.Get(name); got != want {
				t.Errorf("%s = %q, want %q", name, got, want)
			}
		}
		if got := r.Header.Get("X-Wipe-On-Read"); got != "" {
			t.Errorf("obsolete X-Wipe-On-Read sent: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"id":"`+testID+`","created":true}`)
	})
	defer server.Close()

	result, err := client.CreateMessage(context.Background(), CreateMessageRequest{
		MessageID: testID, Envelope: envelope, ContentHash: envelopeHash, DeletionKey: testKey,
		ExpiresAt: client.now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ID != testID || !result.Created {
		t.Fatalf("unexpected result %+v", result)
	}
}

func TestRetrieveReturnsOpaqueBinaryAndMetadata(t *testing.T) {
	envelope := []byte{0xde, 0xad, 0, 0xbe, 0xef}
	const envelopeHash = "035e118749fb0672c2aef735ef0946cf51dd53853b35a80b110c4e0c0a50ccd2"
	client, server := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Wipe-Content-Hash", envelopeHash)
		w.Header().Set("X-Wipe-Cipher-Version", "1")
		_, _ = w.Write(envelope)
	})
	defer server.Close()
	headersObserved := false
	result, err := client.RetrieveMessageWithOptions(context.Background(), testID, TransferOptions{Headers: func(headers RetrievedHeaders) {
		headersObserved = headers.TotalBytes == int64(len(envelope)) && headers.ContentHash == envelopeHash && headers.CipherVersion == 1
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Envelope, envelope) || result.ContentHash != envelopeHash || result.CipherVersion != 1 {
		t.Fatalf("unexpected result %+v", result)
	}
	if !headersObserved {
		t.Fatal("retrieval headers were not observed before body completion")
	}
}

func TestRetrieveRejectsContentHashMismatch(t *testing.T) {
	client, server := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Wipe-Content-Hash", testHash)
		w.Header().Set("X-Wipe-Cipher-Version", "1")
		_, _ = w.Write([]byte{1, 2, 3})
	})
	defer server.Close()
	if _, err := client.RetrieveMessage(context.Background(), testID); err == nil {
		t.Fatal("expected a content-hash mismatch")
	}
}

func TestDeleteAndHealth(t *testing.T) {
	client, server := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodDelete:
			if r.Header.Get("X-Wipe-Deletion-Key") != testKey {
				t.Error("missing deletion key")
			}
			_, _ = io.WriteString(w, `{"deleted":true}`)
		case r.Method == http.MethodGet && r.URL.Path == "/health":
			_, _ = io.WriteString(w, `{"status":"ok"}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})
	defer server.Close()
	deleted, err := client.DeleteMessage(context.Background(), testID, testKey)
	if err != nil || !deleted.Deleted {
		t.Fatalf("delete = %+v, %v", deleted, err)
	}
	health, err := client.Health(context.Background())
	if err != nil || health.Status != "ok" {
		t.Fatalf("health = %+v, %v", health, err)
	}
}

func TestTypedAPIErrorSupportsErrorsAs(t *testing.T) {
	client, server := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "99")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":"Slow down","code":"message_rate_limited","retryAfter":42}`)
	})
	defer server.Close()
	_, err := client.Health(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 429 || apiErr.Code != "message_rate_limited" || apiErr.Message != "Slow down" || apiErr.RetryAfter != 42 {
		t.Fatalf("unexpected APIError %+v", apiErr)
	}
	if extracted, ok := AsAPIError(err); !ok || extracted != apiErr {
		t.Fatal("AsAPIError failed")
	}
}

func TestLegacyErrorPayloadAndRetryHeader(t *testing.T) {
	client, server := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "12")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"error":"Try later"}`)
	})
	defer server.Close()
	_, err := client.Health(context.Background())
	apiErr, ok := AsAPIError(err)
	if !ok || apiErr.Message != "Try later" || apiErr.RetryAfter != 12 {
		t.Fatalf("unexpected error %+v", apiErr)
	}
}

func TestCreateValidatesFreeLimitsBeforeRequest(t *testing.T) {
	requests := 0
	client, server := newTestClient(t, func(http.ResponseWriter, *http.Request) { requests++ })
	defer server.Close()
	valid := CreateMessageRequest{MessageID: testID, Envelope: []byte{1}, DeletionKey: testKey, ExpiresAt: client.now().Add(time.Hour)}

	cases := []struct {
		name   string
		mutate func(*CreateMessageRequest)
	}{
		{"empty", func(r *CreateMessageRequest) { r.Envelope = nil }},
		{"too large", func(r *CreateMessageRequest) { r.Envelope = make([]byte, MaxFreeMessageSize+1) }},
		{"too late", func(r *CreateMessageRequest) { r.ExpiresAt = client.now().Add(MaxFreeExpiry + time.Millisecond) }},
		{"past", func(r *CreateMessageRequest) { r.ExpiresAt = client.now().Add(-time.Second) }},
		{"hash", func(r *CreateMessageRequest) { r.ContentHash = "ABC" }},
		{"key", func(r *CreateMessageRequest) { r.DeletionKey = "no" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := valid
			tc.mutate(&input)
			if _, err := client.CreateMessage(context.Background(), input); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	if requests != 0 {
		t.Fatalf("validation made %d requests", requests)
	}
}

func TestClientIDIsExtensibleButValidated(t *testing.T) {
	for _, value := range []string{"web", "cli", "sdk-go", "mobile-ios", "partner.app_v2"} {
		if _, err := NewClient(ClientOptions{ClientID: value}); err != nil {
			t.Errorf("%q rejected: %v", value, err)
		}
	}
	for _, value := range []string{"Mobile", "-bad", "spaces fail", string(make([]byte, 33))} {
		if _, err := NewClient(ClientOptions{ClientID: value}); err == nil {
			t.Errorf("%q accepted", value)
		}
	}
}

func TestClientRejectsFragmentInBaseURL(t *testing.T) {
	if _, err := NewClient(ClientOptions{BaseURL: "https://wipe.me/#private-secret"}); err == nil {
		t.Fatal("expected private fragment in API base URL to be rejected")
	}
}

func TestCapabilitiesAndNetworkTests(t *testing.T) {
	client, server := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/limits":
			_, _ = io.WriteString(w, `{"authenticated":false,"plan":"anonymous","limits":{"messageBytes":3145728,"maxExpirySeconds":1209600,"devices":0,"apiKeys":0,"messagesPerMinute":3,"uploadBytesPerHour":31457280,"speedTestBytesPerRequest":1048576,"speedTestBytesPerHour":10485760},"usage":null}`)
		case "/api/network-test/upload":
			body, _ := io.ReadAll(r.Body)
			_, _ = io.WriteString(w, fmt.Sprintf(`{"receivedBytes":%d}`, len(body)))
		case "/api/network-test/download":
			if r.URL.Query().Get("bytes") != "64" {
				t.Errorf("unexpected query %s", r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Length", "64")
			_, _ = w.Write(make([]byte, 64))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	defer server.Close()
	limits, err := client.GetLimits(context.Background())
	if err != nil || limits.Limits.MessageBytes != 3145728 {
		t.Fatalf("limits = %+v, %v", limits, err)
	}
	upload, err := client.TestUploadSpeed(context.Background(), make([]byte, 32), nil)
	if err != nil || upload.ReceivedBytes != 32 || upload.BytesPerSecond < 1 {
		t.Fatalf("upload = %+v, %v", upload, err)
	}
	download, err := client.TestDownloadSpeed(context.Background(), 64, nil)
	if err != nil || download.ReceivedBytes != 64 || len(download.Data) != 64 || download.BytesPerSecond < 1 {
		t.Fatalf("download = %+v, %v", download, err)
	}
}

func TestSubmitPerformanceReport(t *testing.T) {
	client, server := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/performance-reports" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected request")
		}
		var report map[string]any
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil || report["flow"] != "create" {
			t.Errorf("invalid body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"accepted":true,"id":"123e4567-e89b-42d3-a456-426614174000"}`)
	})
	defer server.Close()
	encrypt, upload, plaintext, completed, rate := int64(225), int64(920), int64(64000), int64(65536), int64(81920)
	report := PerformanceReport{SchemaVersion: 1, Flow: "create", Result: "success", EncryptedBytes: 65536, PlaintextBytes: &plaintext,
		Estimated:      PerformanceTimings{EncryptMS: &encrypt, UploadMS: &upload, TotalMS: 1145},
		Actual:         PerformanceTimings{EncryptMS: &encrypt, UploadMS: &upload, TotalMS: 1145},
		CompletedBytes: &CompletedBytes{Upload: &completed}, NetworkEstimate: &NetworkEstimate{UploadBytesPerSecond: &rate, SampleAgeMS: 1000},
		EstimateModel: "client-baseline-v1", Client: PerformanceClient{Kind: "sdk-go", Version: "0.4.0", Platform: "server"}}
	result, err := client.SubmitPerformanceReport(context.Background(), report)
	if err != nil || !result.Accepted {
		t.Fatalf("result = %+v, %v", result, err)
	}
	report.Flow = "create"
	report.Result = "integrity_error"
	if _, err := client.SubmitPerformanceReport(context.Background(), report); err == nil {
		t.Fatal("accepted invalid create result")
	}
}
