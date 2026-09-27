# Pocket Action Protocol v1

Pocket Relay consumes declarative transformations, not executable downloaded code.

```json
{
  "schemaVersion": 1,
  "actionID": "PR-0001",
  "summary": "Describe the intended change",
  "preconditions": [{"path":"demo.txt","sha256":"..."}],
  "replacements": [{
    "path":"demo.txt",
    "oldText":"OLD",
    "newText":"NEW",
    "expectedCount":1
  }],
  "postconditions": [{"path":"demo.txt","sha256":"..."}]
}
```

Transaction:
1. Validate action.
2. Verify pre-hashes.
3. Save original bytes.
4. Apply only exact replacements with expected occurrence counts.
5. Verify post-hashes.
6. Restore original bytes on any failure.
7. Emit receipt.
8. Keep Windows acceptance PENDING until verified at home.
