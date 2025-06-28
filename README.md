# user-ingestion

A service for ingesting user data and creating GitHub pull requests. Used by [WATcloud](https://cloud.watonomous.ca).

## Local Development

```sh
docker compose up app --build --watch
```

## Payload Structure

The service expects a JSON payload with the following structure:

```json
{
  "data": {
    "general": {
      "watcloud_username": "johndoe",
      "contact_emails": ["john@example.com", "johndoe@work.com"]
    },
    "other_fields": "can be any additional data"
  }
}
```

### Required Fields
- `data.general.watcloud_username`: String - Unique identifier for the user.
- `data.general.contact_emails`: Array of strings - Non-empty list of contact emails. The first email will be used for email verification.
