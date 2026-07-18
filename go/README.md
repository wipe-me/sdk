# Wipe.me Go SDK

Go module for Wipe.me client-side encryption, private-link capabilities, and the
opaque-message HTTP API, published with module-prefixed semantic-version tags.

Current synchronized pre-release: `github.com/wipe-me/sdk/go@v0.3.0-alpha.1`.

```go
var envelope bytes.Buffer
messageID, err := wipeme.GenerateMessageID()
secret, err := wipeme.GenerateSecret()
encrypted, err := wipeme.Encrypt(
    &envelope,
    messageID,
    secret,
    "Private hello",
    []wipeme.AttachmentInput{{
        Reader: bytes.NewReader(fileBytes),
        Name: "note.txt",
        Type: "text/plain",
        Kind: "text",
        Size: int64(len(fileBytes)),
    }},
)

client, err := wipeme.NewClient(wipeme.ClientOptions{ClientID: "sdk-go"})
created, err := client.CreateMessage(ctx, wipeme.CreateMessageRequest{
    MessageID: messageID,
    Envelope: envelope.Bytes(),
    ContentHash: encrypted.ContentHash,
    DeletionKey: encrypted.DeletionKeyHeader,
    ExpiresAt: time.Now().Add(24 * time.Hour),
})
downloaded, err := client.RetrieveMessage(ctx, messageID)
opened, err := wipeme.Decrypt(bytes.NewReader(downloaded.Envelope), messageID, secret)
deleted, err := client.DeleteMessage(ctx, messageID, opened.DeletionKeyHeader)
```

Non-2xx responses return `*wipeme.APIError`, compatible with `errors.As`, containing
`StatusCode`, stable `Code`, human-readable `Message`, and `RetryAfter` seconds. Free
anonymous messages are validated at 3 MiB and 14 days. The client never sends private
URL-fragment secrets or the obsolete `X-Wipe-On-Read` header.

Production encryption always uses the fixed v1 Argon2id parameters. Readers accept
only the bounded v1 fixture/production range. Attachments stream into encryption;
decryption currently authenticates the complete free-tier envelope in memory.
