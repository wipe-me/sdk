package wipeme

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

type protocolFixture struct {
	MessageID string `json:"message_id"`
	Secret    string `json:"secret"`
	Message   string `json:"message"`
	KDF       struct {
		MemoryKiB   uint32 `json:"memory_kib"`
		Iterations  uint32 `json:"iterations"`
		Parallelism uint8  `json:"parallelism"`
	} `json:"kdf"`
	ExpectedEnvelopeBase64                 string `json:"expected_envelope_base64"`
	ExpectedProductionDeletionKeyBase64URL string `json:"expected_production_deletion_key_base64url"`
}

func loadProtocolFixture(t *testing.T) protocolFixture {
	t.Helper()
	data, err := os.ReadFile("../../fixtures/v1/message-only.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture protocolFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func cheapFixtureOptions(fixture protocolFixture) encryptOptions {
	return encryptOptions{
		random: bytes.NewReader(bytes.Repeat([]byte{0x2a}, 1024)),
		kdf:    KDFParams{MemoryKiB: fixture.KDF.MemoryKiB, Iterations: fixture.KDF.Iterations, Threads: fixture.KDF.Parallelism},
	}
}

func TestEncryptMatchesCanonicalJavaScriptVector(t *testing.T) {
	fixture := loadProtocolFixture(t)
	var encrypted bytes.Buffer
	result, err := encrypt(&encrypted, fixture.MessageID, fixture.Secret, fixture.Message, nil, cheapFixtureOptions(fixture))
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.StdEncoding.EncodeToString(encrypted.Bytes()); got != fixture.ExpectedEnvelopeBase64 {
		t.Fatalf("protocol vector changed:\n%s", got)
	}
	if result.ContentHash == "" || len(result.DeletionKeyHeader) != 43 {
		t.Fatalf("missing envelope capabilities: %#v", result)
	}
}

func TestDecryptReadsCanonicalJavaScriptVector(t *testing.T) {
	fixture := loadProtocolFixture(t)
	envelope, err := base64.StdEncoding.DecodeString(fixture.ExpectedEnvelopeBase64)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Decrypt(bytes.NewReader(envelope), fixture.MessageID, fixture.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Manifest.Message != fixture.Message || len(opened.Attachments) != 0 {
		t.Fatalf("unexpected decrypted result: %#v", opened)
	}
}

func TestProductionDeletionKeyMatchesCanonicalVector(t *testing.T) {
	fixture := loadProtocolFixture(t)
	key, err := DeriveDeletionKey(fixture.MessageID, fixture.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if got := DeletionKeyHeader(key); got != fixture.ExpectedProductionDeletionKeyBase64URL {
		t.Fatalf("deletion key changed: %s", got)
	}
}

func TestAttachmentRoundTripAndTamperRejection(t *testing.T) {
	fixture := loadProtocolFixture(t)
	plaintext := []byte("private attachment")
	attachment := AttachmentInput{Reader: bytes.NewReader(plaintext), Name: "note.txt", Type: "text/plain", Kind: "text", Size: int64(len(plaintext))}
	var encrypted bytes.Buffer
	if _, err := encrypt(&encrypted, fixture.MessageID, fixture.Secret, "attachment", []AttachmentInput{attachment}, cheapFixtureOptions(fixture)); err != nil {
		t.Fatal(err)
	}
	opened, err := Decrypt(bytes.NewReader(encrypted.Bytes()), fixture.MessageID, fixture.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(opened.Attachments) != 1 || !bytes.Equal(opened.Attachments[0].Data, plaintext) {
		t.Fatalf("attachment did not round trip: %#v", opened.Attachments)
	}
	damaged := append([]byte(nil), encrypted.Bytes()...)
	damaged[len(damaged)-2] ^= 1
	if _, err := Decrypt(bytes.NewReader(damaged), fixture.MessageID, fixture.Secret); err == nil {
		t.Fatal("expected tampered ciphertext to fail")
	}
}

func TestEncryptRejectsDuplicateRandomAttachmentIDs(t *testing.T) {
	fixture := loadProtocolFixture(t)
	attachments := []AttachmentInput{
		{Reader: bytes.NewReader([]byte{1}), Size: 1},
		{Reader: bytes.NewReader([]byte{2}), Size: 1},
	}
	if _, err := encrypt(&bytes.Buffer{}, fixture.MessageID, fixture.Secret, "", attachments, cheapFixtureOptions(fixture)); err == nil {
		t.Fatal("expected duplicate random attachment IDs to fail")
	}
}

func TestEncryptRejectsOversizedAttachmentsBeforeReading(t *testing.T) {
	fixture := loadProtocolFixture(t)
	attachment := AttachmentInput{Reader: bytes.NewReader(nil), Size: MaxFreeMessageSize + 1}
	if _, err := encrypt(&bytes.Buffer{}, fixture.MessageID, fixture.Secret, "", []AttachmentInput{attachment}, cheapFixtureOptions(fixture)); err == nil {
		t.Fatal("expected oversized attachment to fail")
	}
}
