# Wipe.me Go SDK

Go module for Wipe.me protocol primitives and the opaque-message HTTP API. It is not
yet tagged for public consumption.

```go
client, err := wipeme.NewClient(wipeme.ClientOptions{ClientID: "sdk-go"})
health, err := client.Health(ctx)
created, err := client.CreateMessage(ctx, wipeme.CreateMessageRequest{
    MessageID: messageID,
    Envelope: envelope,
    DeletionKey: deletionKey,
    ExpiresAt: time.Now().Add(24 * time.Hour),
})
downloaded, err := client.RetrieveMessage(ctx, messageID)
deleted, err := client.DeleteMessage(ctx, messageID, deletionKey)
```

Non-2xx responses return `*wipeme.APIError`, compatible with `errors.As`, containing
`StatusCode`, stable `Code`, human-readable `Message`, and `RetryAfter` seconds. Free
anonymous messages are validated at 3 MiB and 14 days. The client never sends private
URL-fragment secrets or the obsolete `X-Wipe-On-Read` header.
