# JupiterOne SBOM Ingestion Tool

This tool processes CycloneDX Software Bill of Materials (SBOM) files and uploads the data to JupiterOne. It can be used to track dependencies and their relationships in your JupiterOne graph.

## Prerequisites

- Python 3.6+
- [cdxgen](https://github.com/CycloneDX/cdxgen) for SBOM generation (optional)
- JupiterOne account and API credentials
- JupiterOne integration instance ID (if uploading)

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd <repository-directory>
```

2. Create and activate a virtual environment (optional but recommended):
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows, use: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## SBOM Generation

Before using this tool, you need a CycloneDX SBOM file. You can generate one using cdxgen:

1. Install cdxgen:
```bash
npm install -g @cyclonedx/cdxgen
```

2. Generate SBOM:
```bash
cdxgen [REPO_TO_BUILD_SBOM_FOR] -o sbom.json
```

## Configuration

There are three ways to provide configuration (in order of precedence):

1. Command line arguments (highest priority)
2. Environment variables
3. .env file (lowest priority)

### Using a .env File

Create a `.env` file based on the provided `.env.example`:

```bash
cp .env.example .env
```

Edit the `.env` file with your JupiterOne credentials and configuration:

```ini
# JupiterOne Credentials
JUPITERONE_ACCOUNT_ID=your_account_id
JUPITERONE_API_KEY=your_api_key

# JupiterOne Configuration
JUPITERONE_REGION=us
JUPITERONE_INTEGRATION_INSTANCE_ID=your_integration_instance_id
JUPITERONE_TARGET_ENTITY_KEY=your_target_entity_key
JUPITERONE_TARGET_ENTITY_SCOPE=your_target_entity_scope

# Optional: Set logging level (DEBUG, INFO, WARNING, ERROR)
LOG_LEVEL=INFO
```

## Usage

### Process SBOM Only (No Upload)

```bash
python j1_sbom_ingest.py sbom.json output.json
```

### Process and Upload to JupiterOne

Using command line arguments:
```bash
python j1_sbom_ingest.py sbom.json output.json --upload \
  --account-id YOUR_ACCOUNT_ID \
  --api-key YOUR_API_KEY \
  --integration-instance-id YOUR_INSTANCE_ID
```

Using environment variables or .env file:
```bash
python j1_sbom_ingest.py sbom.json output.json --upload
```

### Command Line Arguments

- `sbom_file`: Path to input SBOM file (required)
- `output_file`: Path to output JSON file (required)
- `--upload`: Flag to upload data to JupiterOne
- `--log-level`: Logging level (default: INFO)
- `--account-id`: JupiterOne account ID
- `--api-key`: JupiterOne API key
- `--region`: JupiterOne region (default: us)
- `--integration-instance-id`: JupiterOne integration instance ID
- `--target-entity-key`: Target entity key for relationships
- `--target-entity-scope`: Target entity scope for relationships

## Environment Variables

Instead of command line arguments, you can use environment variables or a .env file:

- `JUPITERONE_ACCOUNT_ID`: Your JupiterOne account ID
- `JUPITERONE_API_KEY`: Your JupiterOne API key
- `JUPITERONE_REGION`: JupiterOne region (default: us)
- `JUPITERONE_INTEGRATION_INSTANCE_ID`: Integration instance ID
- `JUPITERONE_TARGET_ENTITY_KEY`: Target entity key for relationships
- `JUPITERONE_TARGET_ENTITY_SCOPE`: Target entity scope for relationships
- `LOG_LEVEL`: Logging level (default: INFO)

## Output

The tool generates a JSON file containing:
- Entities representing code modules from the SBOM
- Relationships between code modules
- Relationships to a target entity (if specified)

### Entity Properties
- `_type`: Derived from package type (e.g., npm_library)
- `_class`: Always "CodeModule"
- `_key`: Derived from package URL (purl) without version
- Other properties include: description, author, name, licenseType, etc.

### Relationship Properties
- `_type`: "codemodule_contains_codemodule" or "coderepo_contains_codemodule"
- `_class`: "CONTAINS"
- `version`: Version of the dependency
- `_key`: Unique identifier for the relationship

## Error Handling

- The script will exit with code 1 if any errors occur
- Error messages are logged to stderr
- Use `--log-level DEBUG` for more detailed logging
- Authentication errors will only occur when using the upload feature
