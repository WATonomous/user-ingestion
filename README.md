# user-ingestion

A service for ingesting user data and creating pull requests with the data.

## Payload Structure

The service expects a JSON payload with the following structure:

```json
{
  "data": {
    "general": {
      "username": "johndoe",
      "email": "john@example.com",
      "contact_emails": ["john@example.com", "johndoe@work.com"]
    },
    "other_fields": "can be any additional data"
  }
}
```

### Required Fields
- `data.general.username`: String - Unique identifier for the user

### Optional Fields
- `data.general.email`: String - Primary email address (either this or contact_emails is required)
- `data.general.contact_emails`: Array of strings - List of contact emails (will use first one if email is not provided)
- Any additional fields can be included in the `data` object and will be stored as-is

## Local Development

```sh
docker compose up app --build --watch
```
