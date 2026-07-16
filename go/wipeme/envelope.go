package wipeme

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	ManifestLimit     = 16 * 1024 * 1024
	KDFSaltSize       = 32
	DefaultMemoryKiB  = 64 * 1024
	DefaultIterations = 3
	DefaultThreads    = 1
	frameAttachment   = 1
	frameEnd          = 0
)

var envelopeMagic = [8]byte{'W', 'I', 'P', 'E', 'M', 'E', 0, ProtocolVersion}

// KDFParams are authenticated values serialized in the public envelope header.
type KDFParams struct {
	MemoryKiB  uint32
	Iterations uint32
	Threads    uint8
}

// DefaultKDFParams returns the mandatory production v1 Argon2id parameters.
func DefaultKDFParams() KDFParams {
	return KDFParams{MemoryKiB: DefaultMemoryKiB, Iterations: DefaultIterations, Threads: DefaultThreads}
}

// Manifest is encrypted and hidden from the storage service.
type Manifest struct {
	Version     int                  `json:"version"`
	Message     string               `json:"message,omitempty"`
	ChunkSize   int                  `json:"chunk_size"`
	Attachments []AttachmentMetadata `json:"attachments,omitempty"`
}

// AttachmentMetadata is the private presentation and framing metadata for an attachment.
type AttachmentMetadata struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Kind        string `json:"kind"`
	Size        int64  `json:"size"`
	Width       int    `json:"width,omitempty"`
	Height      int    `json:"height,omitempty"`
	Chunks      uint32 `json:"chunks"`
	NoncePrefix string `json:"nonce_prefix"`
}

// AttachmentInput describes one attachment without tying the SDK to local files.
// Reader must yield exactly Size bytes.
type AttachmentInput struct {
	Reader io.Reader
	Name   string
	Type   string
	Kind   string
	Size   int64
	Width  int
	Height int
}

// EncryptResult contains authenticated metadata and server capabilities.
type EncryptResult struct {
	Manifest          Manifest
	DeletionKey       [32]byte
	DeletionKeyHeader string
	ContentHash       string
}

// DecryptedAttachment contains private attachment metadata and plaintext.
type DecryptedAttachment struct {
	Metadata AttachmentMetadata
	Data     []byte
}

// DecryptResult is a completely authenticated in-memory envelope.
type DecryptResult struct {
	Manifest          Manifest
	Attachments       []DecryptedAttachment
	DeletionKey       [32]byte
	DeletionKeyHeader string
}

type encryptOptions struct {
	random io.Reader
	kdf    KDFParams
}

// Encrypt writes a production-parameter v1 envelope to output. The caller should
// discard plaintext buffers and DeletionKey after the create request completes.
func Encrypt(output io.Writer, messageID, secret, message string, attachments []AttachmentInput) (EncryptResult, error) {
	return encrypt(output, messageID, secret, message, attachments, encryptOptions{random: rand.Reader, kdf: DefaultKDFParams()})
}

func encrypt(output io.Writer, messageID, secret, message string, attachments []AttachmentInput, options encryptOptions) (EncryptResult, error) {
	if output == nil {
		return EncryptResult{}, fmt.Errorf("output writer is required")
	}
	if options.random == nil {
		return EncryptResult{}, fmt.Errorf("random source is required")
	}
	if err := validateKDF(options.kdf); err != nil {
		return EncryptResult{}, err
	}
	if err := validateCanonicalCapability(messageID, MessageIDLength, "message ID"); err != nil {
		return EncryptResult{}, err
	}
	if err := validateCanonicalCapability(secret, SecretLength, "secret"); err != nil {
		return EncryptResult{}, err
	}

	manifestNonce := make([]byte, 12)
	if _, err := io.ReadFull(options.random, manifestNonce); err != nil {
		return EncryptResult{}, fmt.Errorf("generate manifest nonce: %w", err)
	}
	manifest := Manifest{Version: ProtocolVersion, Message: message, ChunkSize: ChunkSize}
	rawIDs := make([][]byte, len(attachments))
	usedIDs := make(map[string]struct{}, len(attachments))
	var totalAttachmentSize int64
	for index, attachment := range attachments {
		if attachment.Reader == nil {
			return EncryptResult{}, fmt.Errorf("attachment %d reader is required", index)
		}
		if attachment.Size < 0 {
			return EncryptResult{}, fmt.Errorf("attachment %d has invalid size", index)
		}
		if attachment.Width < 0 || attachment.Height < 0 {
			return EncryptResult{}, fmt.Errorf("attachment %d has invalid dimensions", index)
		}
		if attachment.Size > MaxFreeMessageSize || totalAttachmentSize > MaxFreeMessageSize-attachment.Size {
			return EncryptResult{}, fmt.Errorf("attachments exceed the %d-byte free limit", MaxFreeMessageSize)
		}
		totalAttachmentSize += attachment.Size
		id, err := uniqueAttachmentID(options.random, usedIDs)
		if err != nil {
			return EncryptResult{}, err
		}
		prefix := make([]byte, 8)
		if _, err := io.ReadFull(options.random, prefix); err != nil {
			return EncryptResult{}, fmt.Errorf("generate attachment nonce: %w", err)
		}
		rawIDs[index] = id
		name, contentType, kind := attachment.Name, attachment.Type, attachment.Kind
		if name == "" {
			name = fmt.Sprintf("Attachment %d", index+1)
		}
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		if kind == "" {
			kind = "file"
		}
		manifest.Attachments = append(manifest.Attachments, AttachmentMetadata{
			ID: hex.EncodeToString(id), Name: name, Type: contentType, Kind: kind,
			Size: attachment.Size, Width: attachment.Width, Height: attachment.Height,
			Chunks: chunkCount(attachment.Size), NoncePrefix: hex.EncodeToString(prefix),
		})
	}

	salt := kdfSalt(messageID)
	rootKey := argon2.IDKey([]byte(secret), salt, options.kdf.Iterations, options.kdf.MemoryKiB, options.kdf.Threads, 32)
	defer wipe(rootKey)
	encryptionRoot, err := deriveKey(rootKey, []byte("wipe.me/envelope/v1/encryption"))
	if err != nil {
		return EncryptResult{}, err
	}
	defer wipe(encryptionRoot)
	deletionKey, err := deriveKey(rootKey, []byte("wipe.me/envelope/v1/deletion"))
	if err != nil {
		return EncryptResult{}, err
	}
	defer wipe(deletionKey)
	manifestKey, err := deriveKey(encryptionRoot, []byte("wipe.me/envelope/v1/manifest"))
	if err != nil {
		return EncryptResult{}, err
	}
	defer wipe(manifestKey)
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return EncryptResult{}, fmt.Errorf("encode manifest: %w", err)
	}
	publicHeader := encodePublicHeader(options.kdf, salt, manifestNonce)
	manifestAEAD, err := newGCM(manifestKey)
	if err != nil {
		return EncryptResult{}, err
	}
	manifestCiphertext := manifestAEAD.Seal(nil, manifestNonce, manifestJSON, publicHeader)
	if len(manifestCiphertext) > ManifestLimit {
		return EncryptResult{}, fmt.Errorf("encrypted manifest exceeds %d bytes", ManifestLimit)
	}

	digest := sha256.New()
	writer := &boundedWriter{writer: io.MultiWriter(output, digest), remaining: MaxFreeMessageSize}
	if err := writeFull(writer, publicHeader); err != nil {
		return EncryptResult{}, err
	}
	if err := writeUint32(writer, uint32(len(manifestCiphertext))); err != nil {
		return EncryptResult{}, err
	}
	if err := writeFull(writer, manifestCiphertext); err != nil {
		return EncryptResult{}, err
	}
	for index, attachment := range attachments {
		if err := writeAttachment(writer, encryptionRoot, uint32(index), rawIDs[index], attachment, manifest.Attachments[index]); err != nil {
			return EncryptResult{}, err
		}
	}
	if err := writeFull(writer, []byte{frameEnd}); err != nil {
		return EncryptResult{}, err
	}
	result := EncryptResult{Manifest: manifest, ContentHash: hex.EncodeToString(digest.Sum(nil))}
	copy(result.DeletionKey[:], deletionKey)
	result.DeletionKeyHeader = base64.RawURLEncoding.EncodeToString(result.DeletionKey[:])
	return result, nil
}

func writeAttachment(output io.Writer, encryptionRoot []byte, index uint32, id []byte, input AttachmentInput, metadata AttachmentMetadata) error {
	key, err := deriveKey(encryptionRoot, append([]byte("wipe.me/envelope/v1/attachment/"), id...))
	if err != nil {
		return err
	}
	defer wipe(key)
	aead, err := newGCM(key)
	if err != nil {
		return err
	}
	prefix, _ := hex.DecodeString(metadata.NoncePrefix)
	buffer := make([]byte, ChunkSize)
	remaining := input.Size
	for chunk := uint32(0); chunk < metadata.Chunks; chunk++ {
		plainLength := int64(ChunkSize)
		if remaining < plainLength {
			plainLength = remaining
		}
		plaintext := buffer[:plainLength]
		if _, err := io.ReadFull(input.Reader, plaintext); err != nil {
			return fmt.Errorf("read attachment %q chunk %d: %w", metadata.Name, chunk, err)
		}
		header := encodeFrameHeader(index, chunk, uint32(plainLength))
		ciphertext := aead.Seal(nil, chunkNonce(prefix, chunk), plaintext, chunkAAD(header, metadata.Chunks, id))
		if err := writeFull(output, header); err != nil {
			return err
		}
		if err := writeFull(output, ciphertext); err != nil {
			return err
		}
		remaining -= plainLength
	}
	var extra [1]byte
	if n, readErr := input.Reader.Read(extra[:]); n != 0 || (readErr != nil && readErr != io.EOF) {
		return fmt.Errorf("attachment %q size changed while it was encrypted", metadata.Name)
	}
	return nil
}

// Decrypt authenticates and decrypts a complete v1 envelope.
func Decrypt(input io.Reader, messageID, secret string) (DecryptResult, error) {
	if input == nil {
		return DecryptResult{}, fmt.Errorf("input reader is required")
	}
	if err := validateCanonicalCapability(messageID, MessageIDLength, "message ID"); err != nil {
		return DecryptResult{}, err
	}
	if err := validateCanonicalCapability(secret, SecretLength, "secret"); err != nil {
		return DecryptResult{}, err
	}
	publicHeader := make([]byte, 8+4+4+1+KDFSaltSize+12)
	if _, err := io.ReadFull(input, publicHeader); err != nil {
		return DecryptResult{}, fmt.Errorf("read envelope header: %w", err)
	}
	if !bytes.Equal(publicHeader[:8], envelopeMagic[:]) {
		return DecryptResult{}, fmt.Errorf("unsupported envelope magic or version")
	}
	params := KDFParams{MemoryKiB: binary.BigEndian.Uint32(publicHeader[8:12]), Iterations: binary.BigEndian.Uint32(publicHeader[12:16]), Threads: publicHeader[16]}
	if err := validateKDF(params); err != nil {
		return DecryptResult{}, err
	}
	salt := publicHeader[17 : 17+KDFSaltSize]
	if !bytes.Equal(salt, kdfSalt(messageID)) {
		return DecryptResult{}, fmt.Errorf("envelope does not match message ID")
	}
	manifestNonce := publicHeader[17+KDFSaltSize:]
	manifestLength, err := readUint32(input)
	if err != nil {
		return DecryptResult{}, err
	}
	if manifestLength < 16 || manifestLength > ManifestLimit {
		return DecryptResult{}, fmt.Errorf("invalid encrypted manifest length %d", manifestLength)
	}
	manifestCiphertext := make([]byte, manifestLength)
	if _, err := io.ReadFull(input, manifestCiphertext); err != nil {
		return DecryptResult{}, fmt.Errorf("read encrypted manifest: %w", err)
	}
	rootKey := argon2.IDKey([]byte(secret), salt, params.Iterations, params.MemoryKiB, params.Threads, 32)
	defer wipe(rootKey)
	encryptionRoot, err := deriveKey(rootKey, []byte("wipe.me/envelope/v1/encryption"))
	if err != nil {
		return DecryptResult{}, err
	}
	defer wipe(encryptionRoot)
	deletionKey, err := deriveKey(rootKey, []byte("wipe.me/envelope/v1/deletion"))
	if err != nil {
		return DecryptResult{}, err
	}
	defer wipe(deletionKey)
	manifestKey, err := deriveKey(encryptionRoot, []byte("wipe.me/envelope/v1/manifest"))
	if err != nil {
		return DecryptResult{}, err
	}
	defer wipe(manifestKey)
	aead, err := newGCM(manifestKey)
	if err != nil {
		return DecryptResult{}, err
	}
	manifestJSON, err := aead.Open(nil, manifestNonce, manifestCiphertext, publicHeader)
	if err != nil {
		return DecryptResult{}, fmt.Errorf("invalid secret or damaged envelope")
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		return DecryptResult{}, fmt.Errorf("invalid secret or damaged envelope")
	}
	if manifest.Version != ProtocolVersion || manifest.ChunkSize != ChunkSize {
		return DecryptResult{}, fmt.Errorf("unsupported encrypted manifest version")
	}
	if err := validateManifestAttachments(manifest.Attachments); err != nil {
		return DecryptResult{}, err
	}

	result := DecryptResult{Manifest: manifest, Attachments: make([]DecryptedAttachment, len(manifest.Attachments))}
	copy(result.DeletionKey[:], deletionKey)
	result.DeletionKeyHeader = base64.RawURLEncoding.EncodeToString(result.DeletionKey[:])
	for index, metadata := range manifest.Attachments {
		result.Attachments[index] = DecryptedAttachment{Metadata: metadata, Data: make([]byte, 0, int(metadata.Size))}
		id, _ := hex.DecodeString(metadata.ID)
		prefix, _ := hex.DecodeString(metadata.NoncePrefix)
		key, err := deriveKey(encryptionRoot, append([]byte("wipe.me/envelope/v1/attachment/"), id...))
		if err != nil {
			return DecryptResult{}, err
		}
		attachmentAEAD, err := newGCM(key)
		if err != nil {
			wipe(key)
			return DecryptResult{}, err
		}
		for chunk := uint32(0); chunk < metadata.Chunks; chunk++ {
			header := make([]byte, 13)
			if _, err := io.ReadFull(input, header); err != nil {
				wipe(key)
				return DecryptResult{}, fmt.Errorf("read attachment frame: %w", err)
			}
			plainLength := binary.BigEndian.Uint32(header[9:13])
			if header[0] != frameAttachment || binary.BigEndian.Uint32(header[1:5]) != uint32(index) || binary.BigEndian.Uint32(header[5:9]) != chunk || plainLength > ChunkSize {
				wipe(key)
				return DecryptResult{}, fmt.Errorf("unexpected attachment frame")
			}
			if int64(len(result.Attachments[index].Data))+int64(plainLength) > metadata.Size {
				wipe(key)
				return DecryptResult{}, fmt.Errorf("attachment %d exceeds declared size", index)
			}
			ciphertext := make([]byte, int(plainLength)+attachmentAEAD.Overhead())
			if _, err := io.ReadFull(input, ciphertext); err != nil {
				wipe(key)
				return DecryptResult{}, fmt.Errorf("read encrypted attachment chunk: %w", err)
			}
			plaintext, err := attachmentAEAD.Open(nil, chunkNonce(prefix, chunk), ciphertext, chunkAAD(header, metadata.Chunks, id))
			if err != nil {
				wipe(key)
				return DecryptResult{}, fmt.Errorf("damaged envelope")
			}
			result.Attachments[index].Data = append(result.Attachments[index].Data, plaintext...)
		}
		wipe(key)
		if int64(len(result.Attachments[index].Data)) != metadata.Size {
			return DecryptResult{}, fmt.Errorf("attachment %d size mismatch", index)
		}
	}
	var end [1]byte
	if _, err := io.ReadFull(input, end[:]); err != nil || end[0] != frameEnd {
		return DecryptResult{}, fmt.Errorf("missing envelope end frame")
	}
	var extra [1]byte
	if n, err := input.Read(extra[:]); n != 0 || (err != nil && err != io.EOF) {
		return DecryptResult{}, fmt.Errorf("unexpected data after envelope")
	}
	return result, nil
}

// DeriveDeletionKey reconstructs the production v1 deletion capability.
func DeriveDeletionKey(messageID, secret string) ([32]byte, error) {
	var result [32]byte
	if err := validateCanonicalCapability(messageID, MessageIDLength, "message ID"); err != nil {
		return result, err
	}
	if err := validateCanonicalCapability(secret, SecretLength, "secret"); err != nil {
		return result, err
	}
	params := DefaultKDFParams()
	rootKey := argon2.IDKey([]byte(secret), kdfSalt(messageID), params.Iterations, params.MemoryKiB, params.Threads, 32)
	defer wipe(rootKey)
	key, err := deriveKey(rootKey, []byte("wipe.me/envelope/v1/deletion"))
	if err != nil {
		return result, err
	}
	defer wipe(key)
	copy(result[:], key)
	return result, nil
}

// DeletionKeyHeader encodes a deletion capability for the HTTP API.
func DeletionKeyHeader(key [32]byte) string { return base64.RawURLEncoding.EncodeToString(key[:]) }

func validateCanonicalCapability(value string, length int, label string) error {
	normalized, err := NormalizeBase58(value, length)
	if err != nil || normalized != value {
		return fmt.Errorf("%s must contain %d canonical Base58 characters", label, length)
	}
	return nil
}

func uniqueAttachmentID(random io.Reader, used map[string]struct{}) ([]byte, error) {
	for attempt := 0; attempt < 32; attempt++ {
		id := make([]byte, 16)
		if _, err := io.ReadFull(random, id); err != nil {
			return nil, fmt.Errorf("generate attachment ID: %w", err)
		}
		encoded := hex.EncodeToString(id)
		if _, exists := used[encoded]; !exists {
			used[encoded] = struct{}{}
			return id, nil
		}
	}
	return nil, fmt.Errorf("unable to generate unique attachment ID")
}

func validateManifestAttachments(attachments []AttachmentMetadata) error {
	used := make(map[string]struct{}, len(attachments))
	var totalSize int64
	for index, metadata := range attachments {
		id, err := hex.DecodeString(metadata.ID)
		if err != nil || len(id) != 16 || hex.EncodeToString(id) != metadata.ID {
			return fmt.Errorf("invalid attachment %d ID", index)
		}
		if _, exists := used[metadata.ID]; exists {
			return fmt.Errorf("duplicate attachment ID")
		}
		used[metadata.ID] = struct{}{}
		prefix, err := hex.DecodeString(metadata.NoncePrefix)
		if err != nil || len(prefix) != 8 || hex.EncodeToString(prefix) != metadata.NoncePrefix {
			return fmt.Errorf("invalid attachment %d nonce prefix", index)
		}
		if metadata.Name == "" || metadata.Type == "" || metadata.Kind == "" || metadata.Size < 0 || metadata.Chunks != chunkCount(metadata.Size) || metadata.Width < 0 || metadata.Height < 0 {
			return fmt.Errorf("invalid attachment %d metadata", index)
		}
		if metadata.Size > int64(^uint(0)>>1) {
			return fmt.Errorf("attachment %d is too large for this system", index)
		}
		if metadata.Size > MaxFreeMessageSize || totalSize > MaxFreeMessageSize-metadata.Size {
			return fmt.Errorf("encrypted attachments exceed the %d-byte free limit", MaxFreeMessageSize)
		}
		totalSize += metadata.Size
	}
	return nil
}

type boundedWriter struct {
	writer    io.Writer
	remaining int
}

func (writer *boundedWriter) Write(value []byte) (int, error) {
	if len(value) > writer.remaining {
		return 0, fmt.Errorf("encrypted envelope exceeds the %d-byte free limit", MaxFreeMessageSize)
	}
	n, err := writer.writer.Write(value)
	writer.remaining -= n
	return n, err
}

func kdfSalt(messageID string) []byte {
	digest := sha256.Sum256([]byte("wipe.me/envelope/v1/kdf-salt/" + messageID))
	return digest[:]
}

func encodePublicHeader(params KDFParams, salt, nonce []byte) []byte {
	header := make([]byte, 0, 61)
	header = append(header, envelopeMagic[:]...)
	header = binary.BigEndian.AppendUint32(header, params.MemoryKiB)
	header = binary.BigEndian.AppendUint32(header, params.Iterations)
	header = append(header, params.Threads)
	header = append(header, salt...)
	header = append(header, nonce...)
	return header
}

func encodeFrameHeader(attachment, chunk, plaintextLength uint32) []byte {
	header := []byte{frameAttachment}
	header = binary.BigEndian.AppendUint32(header, attachment)
	header = binary.BigEndian.AppendUint32(header, chunk)
	return binary.BigEndian.AppendUint32(header, plaintextLength)
}

func chunkAAD(header []byte, chunks uint32, id []byte) []byte {
	aad := make([]byte, 0, len(envelopeMagic)+len(header)+4+len(id))
	aad = append(aad, envelopeMagic[:]...)
	aad = append(aad, header...)
	aad = binary.BigEndian.AppendUint32(aad, chunks)
	return append(aad, id...)
}

func chunkNonce(prefix []byte, chunk uint32) []byte {
	nonce := append(make([]byte, 0, 12), prefix...)
	return binary.BigEndian.AppendUint32(nonce, chunk)
}

func chunkCount(size int64) uint32 {
	if size <= 0 {
		return 0
	}
	return uint32((size + ChunkSize - 1) / ChunkSize)
}

func deriveKey(rootKey, info []byte) ([]byte, error) {
	reader := hkdf.New(func() hash.Hash { return sha256.New() }, rootKey, nil, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("derive envelope key: %w", err)
	}
	return key, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize AES: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize AES-GCM: %w", err)
	}
	return aead, nil
}

func validateKDF(params KDFParams) error {
	if params.MemoryKiB < 64 || params.MemoryKiB > DefaultMemoryKiB {
		return fmt.Errorf("invalid Argon2id memory cost %d KiB", params.MemoryKiB)
	}
	if params.Iterations < 1 || params.Iterations > DefaultIterations {
		return fmt.Errorf("invalid Argon2id iteration count %d", params.Iterations)
	}
	if params.Threads != DefaultThreads {
		return fmt.Errorf("invalid Argon2id parallelism %d", params.Threads)
	}
	return nil
}

func writeUint32(writer io.Writer, value uint32) error {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return writeFull(writer, encoded[:])
}

func readUint32(reader io.Reader) (uint32, error) {
	var encoded [4]byte
	if _, err := io.ReadFull(reader, encoded[:]); err != nil {
		return 0, fmt.Errorf("read uint32: %w", err)
	}
	return binary.BigEndian.Uint32(encoded[:]), nil
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return fmt.Errorf("write envelope: %w", err)
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
