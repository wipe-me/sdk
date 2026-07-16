package wipeme

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	MaxFreeMessageSize       = 3 * 1024 * 1024
	MaxFreeExpiry            = 14 * 24 * time.Hour
	DefaultProgressChunkSize = 100 * 1024
)

var (
	clientIDPattern    = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,31}$`)
	contentHashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	deletionKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// Client calls the Wipe.me HTTP API. It is safe for concurrent use.
type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
	clientID   string
	now        func() time.Time
}

// ClientOptions configures a Wipe.me API client.
type ClientOptions struct {
	BaseURL    string
	ClientID   string
	HTTPClient *http.Client
}

// NewClient constructs a client. ClientID is optional extensible producer metadata.
func NewClient(options ClientOptions) (*Client, error) {
	baseURL := strings.TrimSpace(options.BaseURL)
	if baseURL == "" {
		baseURL = "https://wipe.me"
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("invalid base URL %q", baseURL)
	}
	if options.ClientID != "" && !clientIDPattern.MatchString(options.ClientID) {
		return nil, fmt.Errorf("invalid client ID: must match %s", clientIDPattern)
	}
	if options.ClientID == "" {
		options.ClientID = "sdk-go"
	}
	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{baseURL: parsed, httpClient: httpClient, clientID: options.ClientID, now: time.Now}, nil
}

// CreateMessageRequest contains an already-encrypted unified-v1 envelope and metadata.
type CreateMessageRequest struct {
	MessageID         string
	Envelope          []byte
	ContentHash       string
	DeletionKey       string
	ExpiresAt         time.Time
	Progress          ProgressFunc
	ProgressChunkSize int
}

type CreateMessageResult struct {
	ID      string `json:"id"`
	Created bool   `json:"created"`
}

// RetrievedMessage is the opaque encrypted response. Decryption remains client-side.
type RetrievedMessage struct {
	Envelope      []byte
	ContentHash   string
	CipherVersion int
}

type DeleteMessageResult struct {
	Deleted bool `json:"deleted"`
}

type HealthResult struct {
	Status string `json:"status"`
}

// APIError is a non-2xx response and can be selected with errors.As.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
	RetryAfter int
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("wipe.me API error (%d, %s): %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("wipe.me API error (%d): %s", e.StatusCode, e.Message)
}

// AsAPIError extracts a typed API error without requiring callers to import errors.
func AsAPIError(err error) (*APIError, bool) {
	var apiErr *APIError
	ok := errors.As(err, &apiErr)
	return apiErr, ok
}

func (c *Client) CreateMessage(ctx context.Context, input CreateMessageRequest) (*CreateMessageResult, error) {
	id, err := validateMessageID(input.MessageID)
	if err != nil {
		return nil, err
	}
	if len(input.Envelope) == 0 {
		return nil, errors.New("encrypted envelope must not be empty")
	}
	if len(input.Envelope) > MaxFreeMessageSize {
		return nil, fmt.Errorf("encrypted envelope exceeds %d bytes", MaxFreeMessageSize)
	}
	contentHash := input.ContentHash
	if contentHash == "" {
		digest := sha256.Sum256(input.Envelope)
		contentHash = hex.EncodeToString(digest[:])
	}
	if !contentHashPattern.MatchString(contentHash) {
		return nil, errors.New("content hash must be 64 lowercase hexadecimal characters")
	}
	if !deletionKeyPattern.MatchString(input.DeletionKey) {
		return nil, errors.New("deletion key must be 43 base64url characters")
	}
	now := c.now()
	if input.ExpiresAt.IsZero() || !input.ExpiresAt.After(now) {
		return nil, errors.New("expiry must be in the future")
	}
	if input.ExpiresAt.After(now.Add(MaxFreeExpiry)) {
		return nil, errors.New("expiry must not exceed 14 days")
	}

	upload := newProgressReader(bytes.NewReader(input.Envelope), "uploading", int64(len(input.Envelope)), input.Progress, input.ProgressChunkSize)
	req, err := c.request(ctx, http.MethodPut, "/api/messages/"+id, upload)
	if err != nil {
		return nil, err
	}
	req.ContentLength = int64(len(input.Envelope))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Wipe-Content-Hash", contentHash)
	req.Header.Set("X-Wipe-Deletion-Key", input.DeletionKey)
	req.Header.Set("X-Wipe-Cipher-Version", strconv.Itoa(ProtocolVersion))
	req.Header.Set("X-Wipe-Expires-At", strconv.FormatInt(input.ExpiresAt.UnixMilli(), 10))
	c.setClientID(req)

	var result CreateMessageResult
	if err := c.doJSON(req, &result); err != nil {
		return nil, err
	}
	if result.ID != id {
		return nil, errors.New("API returned an unexpected message ID")
	}
	return &result, nil
}

func (c *Client) RetrieveMessage(ctx context.Context, messageID string) (*RetrievedMessage, error) {
	return c.RetrieveMessageWithProgress(ctx, messageID, nil)
}

func (c *Client) RetrieveMessageWithProgress(ctx context.Context, messageID string, progress ProgressFunc) (*RetrievedMessage, error) {
	return c.RetrieveMessageWithOptions(ctx, messageID, TransferOptions{Progress: progress})
}

type TransferOptions struct {
	Progress          ProgressFunc
	ProgressChunkSize int
}

func (c *Client) RetrieveMessageWithOptions(ctx context.Context, messageID string, options TransferOptions) (*RetrievedMessage, error) {
	id, err := validateMessageID(messageID)
	if err != nil {
		return nil, err
	}
	req, err := c.request(ctx, http.MethodGet, "/api/messages/"+id, nil)
	if err != nil {
		return nil, err
	}
	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("retrieve message: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, decodeAPIError(response)
	}
	reader := newProgressReader(response.Body, "downloading", response.ContentLength, options.Progress, options.ProgressChunkSize)
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read encrypted message: %w", err)
	}
	if len(body) == 0 {
		return nil, errors.New("API returned an empty encrypted message")
	}
	contentHash := response.Header.Get("X-Wipe-Content-Hash")
	if !contentHashPattern.MatchString(contentHash) {
		return nil, errors.New("API returned an invalid X-Wipe-Content-Hash header")
	}
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != contentHash {
		return nil, errors.New("encrypted message failed its content-hash integrity check")
	}
	version, err := strconv.Atoi(response.Header.Get("X-Wipe-Cipher-Version"))
	if err != nil || version != ProtocolVersion {
		return nil, fmt.Errorf("invalid X-Wipe-Cipher-Version response header")
	}
	return &RetrievedMessage{Envelope: body, ContentHash: contentHash, CipherVersion: version}, nil
}

type progressReader struct {
	reader                 io.Reader
	phase                  string
	total, processed       int64
	callback               ProgressFunc
	threshold, lastEmitted int64
}

func newProgressReader(source io.Reader, phase string, total int64, callback ProgressFunc, threshold int) *progressReader {
	if threshold == 0 {
		threshold = DefaultProgressChunkSize
	}
	return &progressReader{reader: source, phase: phase, total: total, callback: callback, threshold: int64(threshold), lastEmitted: -1}
}

func (reader *progressReader) Read(value []byte) (int, error) {
	n, err := reader.reader.Read(value)
	reader.processed += int64(n)
	if n > 0 && reader.total >= 0 && (reader.lastEmitted < 0 || reader.processed-reader.lastEmitted >= reader.threshold || reader.processed == reader.total) {
		emitProgress(reader.callback, reader.phase, reader.processed, reader.total, nil, nil)
		reader.lastEmitted = reader.processed
	}
	return n, err
}

func (c *Client) DeleteMessage(ctx context.Context, messageID, deletionKey string) (*DeleteMessageResult, error) {
	id, err := validateMessageID(messageID)
	if err != nil {
		return nil, err
	}
	if !deletionKeyPattern.MatchString(deletionKey) {
		return nil, errors.New("deletion key must be 43 base64url characters")
	}
	req, err := c.request(ctx, http.MethodDelete, "/api/messages/"+id, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Wipe-Deletion-Key", deletionKey)
	var result DeleteMessageResult
	if err := c.doJSON(req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) Health(ctx context.Context) (*HealthResult, error) {
	req, err := c.request(ctx, http.MethodGet, "/health", nil)
	if err != nil {
		return nil, err
	}
	var result HealthResult
	if err := c.doJSON(req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func validateMessageID(value string) (string, error) {
	normalized, err := NormalizeBase58(value, MessageIDLength)
	if err != nil {
		return "", err
	}
	if normalized != value {
		return "", errors.New("message ID must use canonical Base58 without separators")
	}
	return normalized, nil
}

func (c *Client) request(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	target := *c.baseURL
	target.Path = strings.TrimRight(target.Path, "/") + path
	target.RawQuery, target.Fragment = "", ""
	return http.NewRequestWithContext(ctx, method, target.String(), body)
}

func (c *Client) setClientID(req *http.Request) {
	if c.clientID != "" {
		req.Header.Set("X-Wipe-Client", c.clientID)
	}
}

func (c *Client) doJSON(req *http.Request, output any) error {
	response, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", req.Method, req.URL.Path, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return decodeAPIError(response)
	}
	if err := json.NewDecoder(response.Body).Decode(output); err != nil {
		return fmt.Errorf("decode API response: %w", err)
	}
	return nil
}

func decodeAPIError(response *http.Response) error {
	var payload struct {
		Error      string `json:"error"`
		Message    string `json:"message"`
		Code       string `json:"code"`
		RetryAfter int    `json:"retryAfter"`
	}
	_ = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload)
	message := payload.Message
	if message == "" {
		message = payload.Error
	}
	if payload.Code == "" {
		payload.Code = fmt.Sprintf("http_%d", response.StatusCode)
	}
	if message == "" {
		message = http.StatusText(response.StatusCode)
	}
	retryAfter := payload.RetryAfter
	if retryAfter == 0 {
		retryAfter, _ = strconv.Atoi(response.Header.Get("Retry-After"))
	}
	return &APIError{StatusCode: response.StatusCode, Code: payload.Code, Message: message, RetryAfter: retryAfter}
}
