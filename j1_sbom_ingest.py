#!/usr/bin/env python3

import os
import sys
import json
import logging
from typing import Dict, Optional
from dataclasses import dataclass
import argparse
from jupiterone import JupiterOneClient
from urllib.parse import unquote
from dotenv import load_dotenv

@dataclass
class Config:
    """Configuration class for JupiterOne connection and processing"""
    account_id: Optional[str] = None
    api_key: Optional[str] = None
    region: Optional[str] = "us"
    integration_instance_id: Optional[str] = None
    target_entity_key: Optional[str] = None
    target_entity_scope: Optional[str] = None

    @classmethod
    def from_env(cls, require_auth: bool = False) -> 'Config':
        """Create Config from environment variables
        
        Args:
            require_auth: If True, requires account_id and api_key to be set
        """
        # Load .env file if it exists
        load_dotenv(override=True)

        account_id = os.getenv('JUPITERONE_ACCOUNT_ID') or os.getenv('jupiterone_account_id')
        api_key = os.getenv('JUPITERONE_API_KEY') or os.getenv('jupiterone_api_key')
        region = os.getenv('JUPITERONE_REGION') or os.getenv('jupiterone_region', 'us')
        instance_id = os.getenv('JUPITERONE_INTEGRATION_INSTANCE_ID') or os.getenv('jupiterone_integration_instance_id')
        target_key = os.getenv('JUPITERONE_TARGET_ENTITY_KEY') or os.getenv('jupiterone_target_entity_key')
        target_scope = os.getenv('JUPITERONE_TARGET_ENTITY_SCOPE') or os.getenv('jupiterone_target_entity_scope')

        if require_auth and (not account_id or not api_key):
            raise ValueError("JUPITERONE_ACCOUNT_ID and JUPITERONE_API_KEY must be set when using upload feature")

        return cls(
            account_id=account_id,
            api_key=api_key,
            region=region,
            integration_instance_id=instance_id,
            target_entity_key=target_key,
            target_entity_scope=target_scope
        )

    def validate_auth(self) -> None:
        """Validate authentication credentials are present"""
        if not self.account_id or not self.api_key:
            raise ValueError("JUPITERONE_ACCOUNT_ID and JUPITERONE_API_KEY must be set when using upload feature")

def setup_logging(level: str = "INFO") -> logging.Logger:
    """Configure logging"""
    logging_level = getattr(logging, level.upper(), logging.INFO)
    logger = logging.getLogger("sbom-to-j1")
    logger.setLevel(logging_level)
    
    # Create console handler with formatting
    handler = logging.StreamHandler()
    handler.setLevel(logging_level)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    return logger

def parse_sbom(sbom_file: str) -> Dict:
    """Parse SBOM file and return as dictionary"""
    logger = logging.getLogger("sbom-to-j1")
    try:
        with open(sbom_file, 'r', encoding='utf-8') as f:
            sbom_data = json.load(f)
            logger.info(f"Successfully parsed SBOM file: {sbom_file}")
            return sbom_data
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logger.error(f"Error parsing SBOM file: {e}")
        raise

def extract_purl_without_version(purl: str) -> str:
    """Extract PURL without version for entity key"""
    if not purl:
        return ""
    
    # First decode URL encoded characters
    decoded_purl = unquote(purl)
    
    # Handle scoped packages (those with @)
    if '/' in decoded_purl:
        # Split into parts
        base_parts = decoded_purl.rsplit('@', 1)
        if len(base_parts) == 2 and not base_parts[1].startswith('types/'):
            # If there's a version number at the end, remove it
            return base_parts[0]
    
    return decoded_purl

def extract_package_type_from_purl(purl: str) -> str:
    """Extract package type from purl (e.g., 'npm' from 'pkg:npm/package@1.0.0')"""
    if not purl or not purl.startswith('pkg:'):
        return 'unknown'
    try:
        return purl.split('pkg:')[1].split('/')[0]
    except IndexError:
        return 'unknown'

def transform_to_j1_format(sbom_data: Dict, target_entity_key: Optional[str] = None, target_entity_scope: Optional[str] = None) -> Dict:
    """Transform SBOM data into JupiterOne format"""
    logger = logging.getLogger("sbom-to-j1")
    entities = []
    relationships = []
    processed_entities = set()
    processed_relationship_keys = set()

    # Create a mapping of entity keys to their versions and hashes
    version_map = {}
    hash_map = {}
    for component in sbom_data.get('components', []):
        if component.get('purl'):
            key = extract_purl_without_version(component['purl'])
            version = component.get('version', '')
            version_map[key] = version
            
            # Extract SHA-512 hash if available
            for hash_obj in component.get('hashes', []):
                if hash_obj.get('alg') == 'SHA-512':
                    hash_map[key] = hash_obj.get('content', '')
                    break

    def process_component(component: Dict):
        """Process a single component and its dependencies"""
        if not component.get('purl'):
            return

        entity_key = extract_purl_without_version(unquote(component['purl']))
        package_type = extract_package_type_from_purl(component['purl'])
        
        # Skip if we've already processed this entity
        if entity_key in processed_entities:
            return
        
        processed_entities.add(entity_key)

        # Create entity
        name = component.get('name', '')
        group = component.get('group', '')
        display_name = f"{group}/{name}" if group else name

        entity = {
            "description": component.get('description', ''),
            "type": component.get('type', 'library'),
            "scope": component.get('scope', ''),
            "group": component.get('group', ''),
            "author": component.get('authors', [{}])[0].get('name', ''),
            "name": name,
            "displayName": display_name,
            "_class": "CodeModule",
            "_type": f"{package_type}_{component.get('type', 'library')}",
            "_key": entity_key,
            "licenseType": component.get('licenses', [{}])[0].get('license', {}).get('id', ''),
        }

        entities.append(entity)

    # First pass: create all entities
    for component in sbom_data.get('components', []):
        process_component(component)

    # Create set of valid entity keys for validation
    valid_entity_keys = {entity['_key'] for entity in entities}
    if target_entity_key:
        valid_entity_keys.add(target_entity_key)

    # Second pass: create relationships from dependencies
    for dep in sbom_data.get('dependencies', []):
        ref = dep.get('ref')
        depends_on = dep.get('dependsOn', [])
        
        if ref and depends_on:
            from_key = extract_purl_without_version(ref)
            if from_key not in valid_entity_keys:
                logger.debug(f"Skipping relationship: from_key {from_key} not found in entities")
                continue
                
            for dep_ref in depends_on:
                to_key = extract_purl_without_version(dep_ref)
                if to_key not in valid_entity_keys:
                    logger.debug(f"Skipping relationship: to_key {to_key} not found in entities")
                    continue
                    
                version = dep_ref.split('@')[-1] if '@' in dep_ref else ''
                
                relationship_key = f"{from_key}|contains|{to_key}:{version}"
                
                if relationship_key in processed_relationship_keys:
                    logger.debug(f"Skipping duplicate relationship: {relationship_key}")
                    continue
                
                processed_relationship_keys.add(relationship_key)
                
                relationship = {
                    "_key": relationship_key,
                    "_type": "codemodule_contains_codemodule",
                    "_class": "CONTAINS",
                    "_fromEntityKey": from_key,
                    "_toEntityKey": to_key,
                    "version": version,
                    "sha512Hash": hash_map.get(to_key, '')
                }
                relationships.append(relationship)

    # Add relationships to target entity if provided
    if target_entity_key:
        logger.info(f"Adding relationships to target entity: {target_entity_key}")
        all_deps = {rel['_toEntityKey'] for rel in relationships}
        root_nodes = processed_entities - all_deps

        for root_node in root_nodes:
            relationship_key = f"{target_entity_key}|contains|{root_node}"
            
            if relationship_key in processed_relationship_keys:
                logger.debug(f"Skipping duplicate target relationship: {relationship_key}")
                continue
                
            processed_relationship_keys.add(relationship_key)
            
            relationship = {
                "_key": relationship_key,
                "_type": "coderepo_contains_codemodule",
                "_class": "CONTAINS",
                "_fromEntityKey": target_entity_key,
                "_fromEntitySource": "integration-managed",
                "_fromEntityScope": target_entity_scope,
                "_toEntityKey": root_node,
                "version": version_map.get(root_node, ''),
                "sha512Hash": hash_map.get(root_node, '')
            }
            relationships.append(relationship)

    return {
        "data": {
            "entities": entities,
            "relationships": relationships
        }
    }

def upload_to_j1(j1_data: Dict, config: Config) -> bool:
    """Upload data to JupiterOne"""
    logger = logging.getLogger("sbom-to-j1")
    
    if not config.integration_instance_id:
        logger.error("Integration instance ID is required for upload")
        return False

    try:
        # Initialize JupiterOne client
        j1_client = JupiterOneClient(
            account=config.account_id,
            token=config.api_key,
            url=f"https://graphql.{config.region}.jupiterone.io",
            sync_url=f"https://api.{config.region}.jupiterone.io"
        )

        # Start sync job
        logger.info("Starting sync job...")
        sync_job = j1_client.start_sync_job(
            instance_id=config.integration_instance_id,
            sync_mode="CREATE_OR_UPDATE",
            source="integration-managed"
        )
        job_id = sync_job['job']['id']
        logger.info(f"Sync job created with ID: {job_id}")

        # Upload data
        logger.info("Uploading data to JupiterOne...")
        j1_client.upload_combined_batch_json(
            instance_job_id=job_id,
            combined_payload=j1_data['data']
        )

        # Finalize sync job
        logger.info("Finalizing sync job...")
        j1_client.finalize_sync_job(instance_job_id=job_id)
        logger.info("Upload completed successfully")
        return True

    except Exception as e:
        logger.error(f"Error uploading to JupiterOne: {e}")
        return False

def process_sbom(sbom_file: str, output_file: str, config: Config) -> bool:
    """Process SBOM and save to file without uploading"""
    logger = logging.getLogger("sbom-to-j1")
    
    try:
        # Parse SBOM
        sbom_data = parse_sbom(sbom_file)
        
        # Transform to J1 format
        j1_data = transform_to_j1_format(
            sbom_data, 
            config.target_entity_key,
            config.target_entity_scope
        )
        
        # Save to file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(j1_data, f, indent=2)
        
        logger.info(f"Successfully saved transformed data to {output_file}")
        return True
    
    except Exception as e:
        logger.error(f"Error processing SBOM: {e}")
        return False

def process_and_upload_sbom(sbom_file: str, output_file: str, config: Config) -> bool:
    """Process SBOM, save to file, and upload to JupiterOne"""
    logger = logging.getLogger("sbom-to-j1")
    
    try:
        # Parse and transform
        sbom_data = parse_sbom(sbom_file)
        j1_data = transform_to_j1_format(
            sbom_data, 
            config.target_entity_key,
            config.target_entity_scope
        )
        
        # Save to file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(j1_data, f, indent=2)
        logger.info(f"Successfully saved transformed data to {output_file}")
        
        # Upload to JupiterOne
        return upload_to_j1(j1_data, config)
    
    except Exception as e:
        logger.error(f"Error processing and uploading SBOM: {e}")
        return False

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Process SBOM and upload to JupiterOne')
    parser.add_argument('sbom_file', help='Path to SBOM file')
    parser.add_argument('output_file', help='Path to output file')
    parser.add_argument('--upload', action='store_true', help='Upload to JupiterOne')
    parser.add_argument('--log-level', default='INFO', help='Logging level')
    parser.add_argument('--account-id', help='JupiterOne account ID')
    parser.add_argument('--api-key', help='JupiterOne API key')
    parser.add_argument('--region', help='JupiterOne region')
    parser.add_argument('--integration-instance-id', help='JupiterOne integration instance ID')
    parser.add_argument('--target-entity-key', help='Target entity key for relationships')
    parser.add_argument('--target-entity-scope', help='Target entity scope for relationships')
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.log_level)
    
    try:
        # Get configuration from environment
        config = Config.from_env()
        
        # Override with command line arguments if provided
        if args.account_id:
            config.account_id = args.account_id
        if args.api_key:
            config.api_key = args.api_key
        if args.region:
            config.region = args.region
        if args.integration_instance_id:
            config.integration_instance_id = args.integration_instance_id
        if args.target_entity_key:
            config.target_entity_key = args.target_entity_key
        if args.target_entity_scope:
            config.target_entity_scope = args.target_entity_scope
        
        # Process SBOM
        if args.upload:
            if not config.integration_instance_id:
                logger.error("Integration instance ID is required for upload")
                sys.exit(1)
            # Validate auth credentials after all potential sources have been checked
            config.validate_auth()
            success = process_and_upload_sbom(args.sbom_file, args.output_file, config)
        else:
            success = process_sbom(args.sbom_file, args.output_file, config)
        
        sys.exit(0 if success else 1)
        
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()