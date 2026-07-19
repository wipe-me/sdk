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
	MaxSpeedTestSize         = 1024 * 1024
	MaxPerformanceReportSize = 8 * 1024
)

var (
	clientIDPattern      = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,31}$`)
	contentHashPattern   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	deletionKeyPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	estimateModelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	clientVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,31}$`)
	uuidPattern          = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
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

type RetrievedHeaders struct {
	TotalBytes    int64
	ContentHash   string
	CipherVersion int
}

type DeleteMessageResult struct {
	Deleted bool `json:"deleted"`
}

type HealthResult struct {
	Status string `json:"status"`
}

type Limits struct {
	MessageBytes             int64 `json:"messageBytes"`
	MaxExpirySeconds         int64 `json:"maxExpirySeconds"`
	Devices                  int64 `json:"devices"`
	APIKeys                  int64 `json:"apiKeys"`
	MessagesPerMinute        int64 `json:"messagesPerMinute"`
	UploadBytesPerHour       int64 `json:"uploadBytesPerHour"`
	SpeedTestBytesPerRequest int64 `json:"speedTestBytesPerRequest"`
	SpeedTestBytesPerHour    int64 `json:"speedTestBytesPerHour"`
}

type LimitsResult struct {
	Authenticated bool   `json:"authenticated"`
	Plan          string `json:"plan"`
	Limits        Limits `json:"limits"`
	Usage         any    `json:"usage"`
}

type SpeedTestResult struct {
	ReceivedBytes  int64         `json:"receivedBytes"`
	Elapsed        time.Duration `json:"-"`
	BytesPerSecond int64         `json:"-"`
}

type DownloadTestResult struct {
	Data           []byte
	ReceivedBytes  int64
	Elapsed        time.Duration
	BytesPerSecond int64
}

type PerformanceTimings struct {
	EncryptMS  *int64 `json:"encryptMs,omitempty"`
	UploadMS   *int64 `json:"uploadMs,omitempty"`
	DownloadMS *int64 `json:"downloadMs,omitempty"`
	DecryptMS  *int64 `json:"decryptMs,omitempty"`
	TotalMS    int64  `json:"totalMs"`
}

type CompletedBytes struct {
	Upload   *int64 `json:"upload,omitempty"`
	Download *int64 `json:"download,omitempty"`
}

type NetworkEstimate struct {
	UploadBytesPerSecond   *int64 `json:"uploadBytesPerSecond,omitempty"`
	DownloadBytesPerSecond *int64 `json:"downloadBytesPerSecond,omitempty"`
	SampleAgeMS            int64  `json:"sampleAgeMs"`
}

type CryptoEstimate struct {
	EncryptBytesPerSecond *int64 `json:"encryptBytesPerSecond,omitempty"`
	DecryptBytesPerSecond *int64 `json:"decryptBytesPerSecond,omitempty"`
	SampleAgeMS           int64  `json:"sampleAgeMs"`
}

type PerformanceClient struct {
	Kind          string `json:"kind"`
	Version       string `json:"version"`
	Platform      string `json:"platform"`
	BrowserFamily string `json:"browserFamily,omitempty"`
}

type PerformanceReport struct {
	SchemaVersion   int                `json:"schemaVersion"`
	Flow            string             `json:"flow"`
	Result          string             `json:"result"`
	EncryptedBytes  int64              `json:"encryptedBytes"`
	PlaintextBytes  *int64             `json:"plaintextBytes,omitempty"`
	Estimated       PerformanceTimings `json:"estimated"`
	Actual          PerformanceTimings `json:"actual"`
	CompletedBytes  *CompletedBytes    `json:"completedBytes,omitempty"`
	NetworkEstimate *NetworkEstimate   `json:"networkEstimate,omitempty"`
	CryptoEstimate  *CryptoEstimate    `json:"cryptoEstimate,omitempty"`
	EstimateModel   string             `json:"estimateModel"`
	Client          PerformanceClient  `json:"client"`
}

type PerformanceReportResult struct {
	Accepted bool   `json:"accepted"`
	ID       string `json:"id"`
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
	digest := sha256.Sum256(input.Envelope)
	if hex.EncodeToString(digest[:]) != contentHash {
		return nil, errors.New("content hash does not match encrypted envelope")
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
	Headers           func(RetrievedHeaders)
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
	contentHash := response.Header.Get("X-Wipe-Content-Hash")
	if !contentHashPattern.MatchString(contentHash) {
		return nil, errors.New("API returned an invalid X-Wipe-Content-Hash header")
	}
	version, err := strconv.Atoi(response.Header.Get("X-Wipe-Cipher-Version"))
	if err != nil || version != ProtocolVersion {
		return nil, fmt.Errorf("invalid X-Wipe-Cipher-Version response header")
	}
	if options.Headers != nil {
		options.Headers(RetrievedHeaders{TotalBytes: response.ContentLength, ContentHash: contentHash, CipherVersion: version})
	}
	reader := newProgressReader(response.Body, "downloading", response.ContentLength, options.Progress, options.ProgressChunkSize)
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read encrypted message: %w", err)
	}
	if len(body) == 0 {
		return nil, errors.New("API returned an empty encrypted message")
	}
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != contentHash {
		return nil, errors.New("encrypted message failed its content-hash integrity check")
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

func (c *Client) GetLimits(ctx context.Context) (*LimitsResult, error) {
	req, err := c.request(ctx, http.MethodGet, "/api/limits", nil)
	if err != nil {
		return nil, err
	}
	var result LimitsResult
	if err := c.doJSON(req, &result); err != nil {
		return nil, err
	}
	if result.Plan == "" || result.Limits.MessageBytes < 0 || result.Limits.MaxExpirySeconds < 0 || result.Limits.SpeedTestBytesPerRequest < 0 {
		return nil, errors.New("API returned an invalid limits response")
	}
	return &result, nil
}

func (c *Client) TestUploadSpeed(ctx context.Context, sample []byte, progress ProgressFunc) (*SpeedTestResult, error) {
	if len(sample) < 1 || len(sample) > MaxSpeedTestSize {
		return nil, fmt.Errorf("speed-test sample must be between 1 and %d bytes", MaxSpeedTestSize)
	}
	upload := newProgressReader(bytes.NewReader(sample), "uploading", int64(len(sample)), progress, 0)
	req, err := c.request(ctx, http.MethodPost, "/api/network-test/upload", upload)
	if err != nil {
		return nil, err
	}
	req.ContentLength = int64(len(sample))
	req.Header.Set("Content-Type", "application/octet-stream")
	started := time.Now()
	var result SpeedTestResult
	if err := c.doJSON(req, &result); err != nil {
		return nil, err
	}
	result.Elapsed = time.Since(started)
	if result.ReceivedBytes != int64(len(sample)) {
		return nil, errors.New("API returned an invalid upload-test response")
	}
	result.BytesPerSecond = transferRate(result.ReceivedBytes, result.Elapsed)
	return &result, nil
}

func (c *Client) TestDownloadSpeed(ctx context.Context, bytesRequested int, progress ProgressFunc) (*DownloadTestResult, error) {
	if bytesRequested < 1 || bytesRequested > MaxSpeedTestSize {
		return nil, fmt.Errorf("speed-test size must be between 1 and %d bytes", MaxSpeedTestSize)
	}
	req, err := c.request(ctx, http.MethodGet, "/api/network-test/download?bytes="+strconv.Itoa(bytesRequested), nil)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download speed test: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, decodeAPIError(response)
	}
	if response.ContentLength != int64(bytesRequested) || response.Header.Get("Cache-Control") != "no-store" {
		return nil, errors.New("API returned invalid download-test metadata")
	}
	data, err := io.ReadAll(newProgressReader(response.Body, "downloading", int64(bytesRequested), progress, 0))
	if err != nil {
		return nil, fmt.Errorf("read download-test response: %w", err)
	}
	if len(data) != bytesRequested {
		return nil, errors.New("download-test response length did not match Content-Length")
	}
	elapsed := time.Since(started)
	return &DownloadTestResult{Data: data, ReceivedBytes: int64(len(data)), Elapsed: elapsed, BytesPerSecond: transferRate(int64(len(data)), elapsed)}, nil
}

func (c *Client) SubmitPerformanceReport(ctx context.Context, report PerformanceReport) (*PerformanceReportResult, error) {
	if err := validatePerformanceReport(report); err != nil {
		return nil, err
	}
	body, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("encode performance report: %w", err)
	}
	if len(body) > MaxPerformanceReportSize {
		return nil, errors.New("performance report exceeds 8 KiB")
	}
	req, err := c.request(ctx, http.MethodPost, "/api/performance-reports", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")
	var result PerformanceReportResult
	if err := c.doJSON(req, &result); err != nil {
		return nil, err
	}
	if !result.Accepted || !uuidPattern.MatchString(result.ID) {
		return nil, errors.New("API returned an invalid performance-report response")
	}
	return &result, nil
}

func transferRate(bytes int64, elapsed time.Duration) int64 {
	if elapsed <= 0 {
		elapsed = time.Nanosecond
	}
	return int64(float64(bytes) / elapsed.Seconds())
}

func validatePerformanceReport(report PerformanceReport) error {
	if report.SchemaVersion != 1 || (report.Flow != "create" && report.Flow != "open") || report.EncryptedBytes < 1 || report.EncryptedBytes > 1<<30 {
		return errors.New("invalid performance report")
	}
	allowed := map[string]bool{"success": true, "cancelled": true, "transport_error": true}
	if report.Flow == "open" {
		allowed["integrity_error"], allowed["decryption_error"] = true, true
	}
	if !allowed[report.Result] || !estimateModelPattern.MatchString(report.EstimateModel) || !clientIDPattern.MatchString(report.Client.Kind) || !clientVersionPattern.MatchString(report.Client.Version) {
		return errors.New("invalid performance report")
	}
	if report.Client.Platform != "mobile" && report.Client.Platform != "desktop" && report.Client.Platform != "server" && report.Client.Platform != "unknown" {
		return errors.New("invalid performance report")
	}
	if report.Client.BrowserFamily != "" && report.Client.BrowserFamily != "chrome" && report.Client.BrowserFamily != "firefox" && report.Client.BrowserFamily != "safari" && report.Client.BrowserFamily != "edge" && report.Client.BrowserFamily != "other" && report.Client.BrowserFamily != "unknown" {
		return errors.New("invalid performance report")
	}
	if !validPerformanceTimings(report.Estimated, report.Flow, true) || !validPerformanceTimings(report.Actual, report.Flow, report.Result == "success") {
		return errors.New("invalid performance report")
	}
	if report.PlaintextBytes != nil && (*report.PlaintextBytes < 0 || *report.PlaintextBytes > 1<<30) {
		return errors.New("invalid performance report")
	}
	if report.CompletedBytes != nil {
		value := report.CompletedBytes.Upload
		other := report.CompletedBytes.Download
		if report.Flow == "open" {
			value, other = other, value
		}
		if value == nil || other != nil || *value < 0 || *value > report.EncryptedBytes {
			return errors.New("invalid performance report")
		}
	}
	if !validNetworkEstimate(report.NetworkEstimate, report.Flow) || !validCryptoEstimate(report.CryptoEstimate, report.Flow) {
		return errors.New("invalid performance report")
	}
	return nil
}

func validPerformanceTimings(value PerformanceTimings, flow string, required bool) bool {
	if value.TotalMS < 0 || value.TotalMS > 86400000 {
		return false
	}
	wanted, unwanted := []*int64{value.EncryptMS, value.UploadMS}, []*int64{value.DownloadMS, value.DecryptMS}
	if flow == "open" {
		wanted, unwanted = unwanted, wanted
	}
	for _, item := range unwanted {
		if item != nil {
			return false
		}
	}
	for _, item := range wanted {
		if required && item == nil {
			return false
		}
		if item != nil && (*item < 0 || *item > 86400000) {
			return false
		}
	}
	return true
}

func validNetworkEstimate(value *NetworkEstimate, flow string) bool {
	if value == nil {
		return true
	}
	wanted, other := value.UploadBytesPerSecond, value.DownloadBytesPerSecond
	if flow == "open" {
		wanted, other = other, wanted
	}
	return wanted != nil && other == nil && *wanted >= 1 && *wanted <= 1<<40 && value.SampleAgeMS >= 0 && value.SampleAgeMS <= 31536000000
}

func validCryptoEstimate(value *CryptoEstimate, flow string) bool {
	if value == nil {
		return true
	}
	wanted, other := value.EncryptBytesPerSecond, value.DecryptBytesPerSecond
	if flow == "open" {
		wanted, other = other, wanted
	}
	return wanted != nil && other == nil && *wanted >= 1 && *wanted <= 1<<40 && value.SampleAgeMS >= 0 && value.SampleAgeMS <= 31536000000
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
	relative, err := url.Parse(path)
	if err != nil {
		return nil, err
	}
	target.Path = strings.TrimRight(target.Path, "/") + relative.Path
	target.RawQuery, target.Fragment = relative.RawQuery, ""
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
