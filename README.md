# cb20 NetSuite Integration Function

Azure Function that provides a REST endpoint for querying NetSuite data via SuiteQL using Token-Based Authentication (TBA/OAuth 1.0a).

## Architecture
- **Azure Function App** (Flex Consumption) — HTTP trigger endpoint
- **NetSuite REST API** — SuiteQL query interface
- **TBA Authentication** — OAuth 1.0a signature generation

## Tech Stack
- Python 3.11
- Azure Functions v2
- NetSuite SuiteTalk REST Web Services

## Setup
1. Clone the repo
2. Create a NetSuite integration record with TBA enabled
3. Generate access token and credentials
4. Set the following constants in `netsuite_query/__init__.py`:
   - `ACCOUNT_ID`
   - `CONSUMER_KEY`
   - `CONSUMER_SECRET`
   - `TOKEN_ID`
   - `TOKEN_SECRET`
5. Deploy to Azure Functions using GitHub Actions

## Usage
POST to the function endpoint with a JSON body:
```json
{
  "query": "SELECT id, companyName FROM customer LIMIT 10"
}
```

## CI/CD
Automated deployment via GitHub Actions on push to main branch.