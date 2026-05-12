# Security Specification - NutriSense AI

## 1. Data Invariants
- A user can only access their own profile (`users/{userId}` where `userId == auth.uid`).
- A meal log or water log must be associated with the authenticated user's ID (`userId == auth.uid`).
- Users cannot modify their `uid` or `email` once set in their profile.
- Timestamps (`updatedAt`, `timestamp`, `loggedAt`) must be validated against `request.time`.

## 2. The "Dirty Dozen" Payloads
1. **Identity Spoofing**: Attempt to create a user profile with a `uid` that doesn't match the auth token.
2. **Resource Poisoning**: Attempt to inject a 1MB string into the `foodName` field of a `mealLog`.
3. **Cross-User Leak**: Attempt to read another user's `mealLogs` by querying without a `userId` filter.
4. **State Shortcutting**: Attempt to update a `mealLog`'s `calories` without being the owner.
5. **PII Leak**: Attempt to read the `users` collection without being authenticated.
6. **Self-Assigned Admin**: Attempt to set an `isAdmin` field in the user profile (even if the app doesn't currently use it, we check for it).
7. **Orphaned Writes**: Attempt to create a `mealLog` with a `userId` that doesn't exist in the `users` collection.
8. **Shadow Field Injection**: Attempt to create a `MealLog` with an extra `isVerified` field not in the schema.
9. **Timestamp Spoofing**: Attempt to set a `timestamp` in the past when creating a log.
10. **Immortal Field Update**: Attempt to change the `userId` of an existing `mealLog`.
11. **Massive Array Injection**: (N/A for this app, but checking for size limits on all fields).
12. **Unverified Email Access**: Attempt to write to a log with an unverified email (assuming verification is required).

## 3. Conflict Report & Mitigation
| Vulnerability | Mitigation |
| :--- | :--- |
| Identity Spoofing | `userId == request.auth.uid` check |
| Shadow Field Injection | `keys().hasOnly()` or `keys().size()` check in validation helpers |
| Resource Poisoning | `.size() <= MAX` check on all string fields |
| Query Trust | `allow list: if resource.data.userId == request.auth.uid` |
