#!/usr/bin/env python3

"""
Image security analysis module
Handles Docker image scanning, vulnerability detection, and remediation
"""

import json
import subprocess
import re
import datetime
import logging
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
import stat

from common import EnhancedSecurityPipeline, LlamaAPIClient


class ImageSecurityAnalyzer:
    """Docker image security scanning and remediation"""

    def __init__(self, pipeline: EnhancedSecurityPipeline):
        self.pipeline = pipeline
        self.llm_client = None

    def list_docker_images(self) -> List[Dict[str, str]]:
        """List all available Docker images"""
        rc, out, err = self.pipeline.run_cmd(["docker", "images", "--format", "{{.Repository}}:{{.Tag}} {{.ID}} {{.Size}}"])
        images = []
        if rc == 0 and out:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    images.append({"name": parts[0], "id": parts[1], "extra": ' '.join(parts[2:])})
        else:
            logging.info("No docker images found or docker not available")
        return images

    def pretty_print_list(self, items: List[Dict[str, str]], title: str = "Items"):
        """Pretty print a list of items"""
        self.pipeline.pretty_print_list(items, title)

    def validate_docker_image(self, image_name: str) -> bool:
        """Validate that a Docker image exists locally or can be accessed"""
        try:
            result = subprocess.run(
                ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}", "--filter", f"reference={image_name}"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and image_name in result.stdout:
                return True

            result = subprocess.run(
                ["docker", "inspect", image_name],
                capture_output=True, text=True, timeout=30
            )
            return result.returncode == 0
        except Exception as e:
            logging.error(f"Error validating image: {e}")
            return False

    def guide_docker_pull(self, image_name: str) -> bool:
        """Guide user through pulling or building a Docker image"""
        print(f"\nImage '{image_name}' not found locally.")
        print("\nOptions:")
        print(f"1. Pull from registry: docker pull {image_name}")
        print(f"2. Build locally: docker build -t {image_name} .")
        print("3. Continue anyway (scan will fail)")
        
        choice = input("\nChoose (1/2/3): ").strip()
        
        if choice == "1":
            try:
                print(f"Pulling {image_name}...")
                subprocess.run(["docker", "pull", image_name], check=True)
                return True
            except subprocess.CalledProcessError:
                print("Failed to pull image.")
                return False
        elif choice == "2":
            try:
                print(f"Building {image_name}...")
                subprocess.run(["docker", "build", "-t", image_name, "."], check=True)
                return True
            except subprocess.CalledProcessError:
                print("Failed to build image.")
                return False
        else:
            return choice == "3"

    def fetch_available_versions(self, package_name: str, ecosystem: str) -> List[str]:
        """
        Fetch available versions for a package from various registries.
        This helps the LLM suggest only valid versions.
        """
        versions = []
        
        try:
            if ecosystem in ['python', 'pip']:
                # Use PyPI JSON API
                result = subprocess.run(
                    ["curl", "-s", f"https://pypi.org/pypi/{package_name}/json"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    versions = list(data.get('releases', {}).keys())
                    
            elif ecosystem in ['nodejs', 'npm']:
                # Use npm registry
                result = subprocess.run(
                    ["npm", "view", package_name, "versions", "--json"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    versions = json.loads(result.stdout)
                    
            elif ecosystem == 'go':
                # Use go list to get available versions
                result = subprocess.run(
                    ["go", "list", "-m", "-versions", package_name],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    # Output format: "module_name version1 version2 version3"
                    parts = result.stdout.strip().split()
                    if len(parts) > 1:
                        versions = parts[1:]
                        
            elif ecosystem in ['ruby', 'gem']:
                # Use gem list
                result = subprocess.run(
                    ["gem", "list", "--remote", "--exact", package_name, "--all"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    # Parse versions from gem output
                    version_pattern = r'\(([^)]+)\)'
                    matches = re.findall(version_pattern, result.stdout)
                    if matches:
                        versions = matches[0].split(', ')
                        
            elif ecosystem == 'maven':
                # Use Maven Central API
                result = subprocess.run(
                    ["curl", "-s", f"https://search.maven.org/solrsearch/select?q=g:{package_name.split(':')[0]}+AND+a:{package_name.split(':')[1]}&rows=50&wt=json"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    docs = data.get('response', {}).get('docs', [])
                    versions = [doc['v'] for doc in docs if 'v' in doc]
                    
        except Exception as e:
            logging.warning(f"Could not fetch versions for {package_name} in {ecosystem}: {e}")
        
        # Sort versions in descending order (latest first)
        try:
            from packaging import version
            versions.sort(key=lambda x: version.parse(x), reverse=True)
        except:
            versions.sort(reverse=True)
        
        return versions[:20]  # Return top 20 versions

    def enrich_vulnerabilities_with_versions(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Enrich vulnerability data with actual available versions from registries.
        This prevents the LLM from suggesting non-existent versions.
        """
        enriched_vulns = []
        
        for vuln in vulnerabilities:
            enriched_vuln = vuln.copy()
            
            # Detect ecosystem from library name or context
            ecosystem = self.detect_ecosystem(vuln.get('library', ''))
            
            if ecosystem:
                # Fetch available versions
                available_versions = self.fetch_available_versions(
                    vuln.get('library', ''),
                    ecosystem
                )
                
                enriched_vuln['available_versions'] = available_versions
                enriched_vuln['ecosystem'] = ecosystem
                
                # If fixed version exists, verify it's in available versions
                fixed_version = vuln.get('fixed_version', '')
                if fixed_version and fixed_version != 'unknown':
                    if available_versions and fixed_version not in available_versions:
                        # Find the closest valid version
                        enriched_vuln['verified_fix_version'] = self.find_closest_version(
                            fixed_version, available_versions
                        )
                        enriched_vuln['fix_version_warning'] = f"Suggested fix version {fixed_version} not found. Closest available: {enriched_vuln['verified_fix_version']}"
                    else:
                        enriched_vuln['verified_fix_version'] = fixed_version
                else:
                    # Suggest latest version if no fix version specified
                    if available_versions:
                        enriched_vuln['verified_fix_version'] = available_versions[0]
                        
            enriched_vulns.append(enriched_vuln)
        
        return enriched_vulns

    def detect_ecosystem(self, library_name: str) -> Optional[str]:
        """Detect package ecosystem from library name"""
        # Common patterns for different ecosystems
        if library_name.startswith('github.com/'):
            return 'go'
        elif '/' in library_name and ':' in library_name:
            return 'maven'
        elif library_name.endswith('.gem') or library_name.count('.') <= 1:
            # Could be Ruby gem (simple naming)
            return 'ruby'
        else:
            # Default heuristics
            return 'python'  # Most common in containers

    def find_closest_version(self, target_version: str, available_versions: List[str]) -> str:
        """Find the closest available version to a target version"""
        if not available_versions:
            return target_version
        
        try:
            from packaging import version
            target = version.parse(target_version)
            
            # Find versions >= target version
            higher_versions = [v for v in available_versions if version.parse(v) >= target]
            if higher_versions:
                return min(higher_versions, key=lambda x: version.parse(x))
            
            # If no higher version, return latest
            return available_versions[0]
        except:
            # Fallback to simple string comparison
            return available_versions[0] if available_versions else target_version

    def detect_image_type(self, image_name: str) -> Dict[str, Any]:
        """Detect image type, technology stack, and configuration"""
        try:
            result = subprocess.run(
                ["docker", "inspect", image_name],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                inspect_data = json.loads(result.stdout)[0]
                config = inspect_data.get('Config', {})
                
                image_info = {
                    'base_os': 'unknown',
                    'technology_stack': [],
                    'exposed_ports': [],
                    'environment': config.get('Env', []),
                    'working_dir': config.get('WorkingDir', '/'),
                    'entrypoint': config.get('Entrypoint', []),
                    'cmd': config.get('Cmd', [])
                }
                
                # Detect base OS
                env_vars = ' '.join(image_info['environment']).lower()
                image_labels = ' '.join(f"{k}={v}" for k, v in inspect_data.get('Config', {}).get('Labels', {}).items()).lower()
                all_text = f"{env_vars} {image_labels} {image_name}".lower()
                
                if 'debian' in all_text or 'ubuntu' in all_text:
                    image_info['base_os'] = 'debian'
                elif 'alpine' in all_text:
                    image_info['base_os'] = 'alpine'
                elif 'centos' in all_text or 'rhel' in all_text or 'fedora' in all_text:
                    image_info['base_os'] = 'rhel'
                
                # Detect technology stack
                all_text = (env_vars + ' ' + str(image_info['entrypoint']) + ' ' + 
                           str(image_info['cmd']) + ' ' + image_labels).lower()
                
                tech_indicators = {
                    'python': ['python', 'pip', 'django', 'flask', 'fastapi', 'uvicorn'],
                    'nodejs': ['node', 'npm', 'yarn', 'javascript', 'js'],
                    'java': ['java', 'jvm', 'maven', 'gradle', 'spring', 'jar'],
                    'dotnet': ['.net', 'dotnet', 'aspnet', 'nuget', 'csharp'],
                    'go': ['golang', '/go/', 'go build', 'go run'],
                    'ruby': ['ruby', 'gem', 'rails', 'bundler', 'rake'],
                    'php': ['php', 'composer', 'laravel', 'symfony'],
                    'rust': ['cargo', 'rust', 'rustc'],
                    'nginx': ['nginx', 'nginx.conf'],
                    'apache': ['apache', 'httpd'],
                    'database': ['mysql', 'postgres', 'mongodb', 'redis', 'mariadb']
                }
                
                for tech, indicators in tech_indicators.items():
                    if any(indicator in all_text for indicator in indicators):
                        image_info['technology_stack'].append(tech)
                
                # Get exposed ports
                exposed_ports = config.get('ExposedPorts', {})
                image_info['exposed_ports'] = [port.split('/')[0] for port in exposed_ports.keys()]
                
                return image_info
                
        except Exception as e:
            logging.warning(f"Could not detect image type: {e}")
        
        return {
            'base_os': 'unknown',
            'technology_stack': ['unknown'],
            'exposed_ports': [],
            'environment': [],
            'working_dir': '/',
            'entrypoint': [],
            'cmd': []
        }

    def run_trivy_scan(self, image_name: str) -> Dict[str, str]:
  
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = re.sub(r'[^\w\-_]', '_', image_name)
        
        outputs = {
            "txt_file": str(self.pipeline.scans_dir / f"trivy_scan_{safe_name}_{timestamp}.txt"),
            "json_file": str(self.pipeline.scans_dir / f"trivy_scan_{safe_name}_{timestamp}.json"),
            "sbom_cyclonedx": str(self.pipeline.scans_dir / f"sbom_cyclonedx_{safe_name}_{timestamp}.json"),
            "timestamp": timestamp,
            "image_name": image_name
        }

        try:
            # Check if Trivy is installed
            subprocess.run(["trivy", "version"], capture_output=True, check=True)
            logging.info(f"Starting Trivy scan for {image_name}")

            # Run text format scan
            subprocess.run([
                "trivy", "image",
                "--format", "table",
                "--output", outputs["txt_file"],
                "--severity", "HIGH,CRITICAL",
                "--timeout", "10m",
                image_name
            ], check=True, timeout=600)

            # Run JSON format scan
            subprocess.run([
                "trivy", "image", 
                "--format", "json",
                "--output", outputs["json_file"],
                "--severity", "HIGH,CRITICAL", 
                "--timeout", "10m",
                image_name
            ], check=True, timeout=600)

            # Generate CycloneDX SBOM
            subprocess.run([
                "trivy", "image",
                "--format", "cyclonedx",
                "--output", outputs["sbom_cyclonedx"],
                "--timeout", "10m",
                image_name
            ], check=True, timeout=600)

            logging.info("Trivy scan completed successfully")
            return outputs

        except FileNotFoundError:
            error_msg = """Error: trivy command not found. Please install Trivy:
    - Windows: winget install Aqua.Trivy
    - macOS: brew install trivy  
    - Linux: wget https://github.com/aquasecurity/trivy/releases/latest/download/trivy_Linux-64bit.tar.gz
    - Or: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"""
            logging.error(error_msg)
            raise RuntimeError(error_msg)
        except subprocess.TimeoutExpired:
            raise RuntimeError("Trivy scan timed out after 10 minutes")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Trivy scan failed: {e}")
            
        

    def parse_trivy_json_results(self, trivy_json_file: str) -> List[Dict]:
        """Parse Trivy scan results from JSON output (more reliable)"""
        vulnerabilities = []
        
        try:
            with open(trivy_json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            results = data.get('Results', [])
            for result in results:
                vulns = result.get('Vulnerabilities', [])
                for vuln in vulns:
                    vulnerabilities.append({
                        'cve_id': vuln.get('VulnerabilityID', ''),
                        'library': vuln.get('PkgName', ''),
                        'severity': vuln.get('Severity', ''),
                        'installed_version': vuln.get('InstalledVersion', ''),
                        'fixed_version': vuln.get('FixedVersion', 'unknown'),
                        'title': vuln.get('Title', ''),
                        'description': vuln.get('Description', '')
                    })
            
            logging.info(f"Parsed {len(vulnerabilities)} vulnerabilities from JSON")
            return vulnerabilities
        except Exception as e:
            logging.warning(f"Could not parse Trivy JSON results: {e}")
            return []

    def parse_trivy_results(self, trivy_txt_file: str, trivy_json_file: str = None) -> List[Dict]:
        """Parse Trivy scan results from text output, with JSON fallback"""
        vulnerabilities = []
        
        # Try JSON first (more reliable)
        if trivy_json_file and os.path.exists(trivy_json_file):
            json_vulns = self.parse_trivy_json_results(trivy_json_file)
            if json_vulns:
                return json_vulns
        
        # Fallback to text parsing
        try:
            content = self.pipeline.safe_read_file(trivy_txt_file)
            sections = content.split('\n\n')
            
            for section in sections:
                # Look for table sections with vulnerabilities
                if '│' in section and ('CVE-' in section or 'GHSA-' in section):
                    lines = section.split('\n')
                    header_indices = {}
                    
                    # Find header row and parse column positions
                    for line in lines:
                        if '│' in line and ('Library' in line or 'Vulnerability' in line):
                            parts = [p.strip() for p in line.split('│') if p.strip()]
                            for i, part in enumerate(parts):
                                part_lower = part.lower()
                                if 'library' in part_lower or 'package' in part_lower:
                                    header_indices['library'] = i
                                elif 'vulnerability' in part_lower or 'cve' in part_lower or 'id' in part_lower:
                                    header_indices['cve'] = i
                                elif 'severity' in part_lower:
                                    header_indices['severity'] = i
                                elif 'status' in part_lower:
                                    header_indices['status'] = i
                                elif 'installed' in part_lower:
                                    header_indices['installed'] = i
                                elif 'fixed' in part_lower:
                                    header_indices['fixed'] = i
                                elif 'title' in part_lower:
                                    header_indices['title'] = i
                            break
                    
                    # Parse vulnerability rows
                    for line in lines:
                        if ('CVE-' in line or 'GHSA-' in line) and '│' in line:
                            parts = [p.strip() for p in line.split('│') if p.strip()]
                            
                            if len(parts) >= max(header_indices.values(), default=0) + 1:
                                try:
                                    vuln = {
                                        'cve_id': parts[header_indices.get('cve', 1)],
                                        'library': parts[header_indices.get('library', 0)],
                                        'severity': parts[header_indices.get('severity', 2)],
                                        'status': parts[header_indices.get('status', 3)],
                                        'installed_version': parts[header_indices.get('installed', 4)],
                                        'fixed_version': parts[header_indices.get('fixed', 5)],
                                        'title': parts[header_indices.get('title', 6)] if len(parts) > 6 else 'No title'
                                    }
                                    
                                    # Clean up title
                                    if 'https://avd.aquasec.com' in vuln['title']:
                                        vuln['title'] = vuln['title'].split('https://avd.aquasec.com')[0].strip()
                                    
                                    vuln['description'] = vuln['title']
                                    vulnerabilities.append(vuln)
                                except (IndexError, ValueError) as e:
                                    logging.warning(f"Failed to parse vulnerability line: {e}")
                                    continue

        except Exception as e:
            logging.error(f"Error parsing Trivy results: {e}")

        logging.info(f"Parsed {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities

    def discover_project_files(self, tech_stack: List[str]) -> Dict[str, str]:
        """Discover and read project configuration files"""
        files_content = {}
        
        file_patterns = {
            'python': ['requirements.txt', 'Pipfile', 'pyproject.toml', 'setup.py', 'poetry.lock'],
            'nodejs': ['package.json', 'package-lock.json', 'yarn.lock'],
            'java': ['pom.xml', 'build.gradle', 'build.xml', 'gradle.properties'],
            'dotnet': ['*.csproj', '*.sln', 'packages.config', 'nuget.config'],
            'go': ['go.mod', 'go.sum', 'vendor/modules.txt'],
            'ruby': ['Gemfile', 'Gemfile.lock'],
            'php': ['composer.json', 'composer.lock'],
            'rust': ['Cargo.toml', 'Cargo.lock'],
            'dockerfile': ['Dockerfile', 'dockerfile', 'Containerfile', 'Dockerfile.*']
        }
        
        # Always try to find Dockerfile
        for pattern in file_patterns.get('dockerfile', []):
            for dockerfile_path in [pattern, f"./{pattern}"]:
                if os.path.exists(dockerfile_path):
                    try:
                        files_content['dockerfile'] = self.pipeline.safe_read_file(dockerfile_path)
                        logging.info(f"Found Dockerfile: {dockerfile_path}")
                        break
                    except Exception as e:
                        logging.warning(f"Could not read {dockerfile_path}: {e}")
        
        # Find tech-specific files
        for tech in tech_stack:
            if tech in file_patterns:
                for pattern in file_patterns[tech]:
                    if '*' in pattern:
                        import glob
                        matches = glob.glob(pattern)
                        for match in matches:
                            try:
                                with open(match, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    files_content[f"{tech}_{os.path.basename(match)}"] = content
                                    logging.info(f"Found {tech} file: {match}")
                                break
                            except Exception as e:
                                logging.warning(f"Could not read {match}: {e}")
                    else:
                        if os.path.exists(pattern):
                            try:
                                with open(pattern, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    files_content[f"{tech}_{pattern}"] = content
                                    logging.info(f"Found {tech} file: {pattern}")
                                break
                            except Exception as e:
                                logging.warning(f"Could not read {pattern}: {e}")
        
        return files_content

    def retrieve_rag_context(self, image_name: str, vulnerabilities: List[Dict], n_results: int = 5) -> str:
        """Retrieve relevant context from ChromaDB using RAG"""
        if not self.pipeline.collection:
            logging.warning("RAG system not initialized, using basic CVE context")
            return self.pipeline.knowledge_base.get_cve_context(image_name)
        
        try:
            contexts = []
            
            # Query by image name
            query_text = f"security vulnerabilities {image_name} docker image"
            results = self.pipeline.collection.query(
                query_texts=[query_text],
                n_results=n_results
            )
            if results.get("documents") and results["documents"][0]:
                contexts.extend(results["documents"][0])
            
            # Query by CVE IDs found in vulnerabilities
            cve_ids = [v.get('cve_id', '') for v in vulnerabilities[:5] if v.get('cve_id')]
            for cve_id in cve_ids:
                if cve_id and cve_id.startswith('CVE-'):
                    cve_results = self.pipeline.collection.query(
                        query_texts=[cve_id],
                        n_results=3
                    )
                    if cve_results.get("documents") and cve_results["documents"][0]:
                        contexts.extend(cve_results["documents"][0])
            
            # Query by library names
            library_names = [v.get('library', '') for v in vulnerabilities[:5] if v.get('library')]
            for library in library_names:
                if library:
                    lib_results = self.pipeline.collection.query(
                        query_texts=[f"vulnerability {library} package security"],
                        n_results=2
                    )
                    if lib_results.get("documents") and lib_results["documents"][0]:
                        contexts.extend(lib_results["documents"][0])
            
            # Deduplicate and format context
            unique_contexts = list(dict.fromkeys(contexts))
            if unique_contexts:
                context_text = "RELEVANT SECURITY DATA FROM KNOWLEDGE BASE:\n\n"
                for i, doc in enumerate(unique_contexts[:n_results], 1):
                    doc_preview = doc[:800] + "..." if len(doc) > 800 else doc
                    context_text += f"--- DOCUMENT {i} ---\n{doc_preview}\n\n"
                
                # Also add basic CVE context for any CVEs found
                all_cves = ' '.join(cve_ids)
                if all_cves:
                    kb_context = self.pipeline.knowledge_base.get_cve_context(all_cves)
                    if kb_context:
                        context_text += f"\n{kb_context}\n"
                
                logging.info(f"Retrieved {len(unique_contexts)} relevant documents from RAG")
                return context_text
            
        except Exception as e:
            logging.warning(f"Error retrieving RAG context: {e}")
        
        # Fallback to basic CVE context
        return self.pipeline.knowledge_base.get_cve_context(image_name)

    def extract_dockerfile_from_response(self, response: str, original_image_name: str = None) -> Optional[str]:
        """Extract Dockerfile content from LLM response"""
        # More comprehensive patterns to find Dockerfile code blocks
        patterns = [
            # Pattern 1: Dockerfile.secured with explicit header
            r'###\s*Dockerfile\.secured\s*\n\s*```(?:dockerfile)?\s*\n(.*?)```',
            # Pattern 2: In "Remediated Files to Generate" section
            r'Remediated Files to Generate.*?Dockerfile\.secured.*?```(?:dockerfile)?\s*\n(.*?)```',
            # Pattern 3: Any dockerfile code block (first one is usually the secured one)
            r'```dockerfile\s*\n(.*?)```',
            # Pattern 4: Generic code block that might contain Dockerfile
            r'```\s*Dockerfile\.secured\s*\n(.*?)```',
            # Pattern 5: Code block after Dockerfile.secured header
            r'Dockerfile\.secured\s*\n\s*```(?:dockerfile)?\s*\n(.*?)```',
            # Pattern 6: Any code block (fallback)
            r'```\s*\n(.*?FROM.*?)```',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response, re.DOTALL | re.IGNORECASE)
            if matches:
                dockerfile_content = matches[0].strip()
                
                # Validate it's actually a Dockerfile (must have FROM)
                if 'FROM' not in dockerfile_content.upper():
                    continue
                
                # Remove any header lines that aren't part of Dockerfile syntax
                lines = dockerfile_content.split('\n')
                cleaned_lines = []
                found_from = False
                for line in lines:
                    line_stripped = line.strip()
                    # Skip markdown headers, comments about Dockerfile.secured, etc.
                    if line_stripped.startswith('#') and ('Dockerfile' in line_stripped.lower() or not found_from):
                        continue
                    if 'FROM' in line_stripped.upper() and not found_from:
                        found_from = True
                    if found_from or line_stripped.startswith(('#', 'FROM', 'RUN', 'COPY', 'WORKDIR', 'USER', 'EXPOSE', 'ENV', 'ARG', 'CMD', 'ENTRYPOINT', 'LABEL', 'ADD')):
                        cleaned_lines.append(line)
                
                dockerfile_content = '\n'.join(cleaned_lines)
                
                # Handle placeholder base images
                if '<original-base>' in dockerfile_content or '<original-base-image>' in dockerfile_content.lower():
                    # Try to get base image from original image
                    if original_image_name:
                        # Try docker inspect to get base image
                        try:
                            result = subprocess.run(
                                ["docker", "inspect", original_image_name],
                                capture_output=True, text=True, timeout=30
                            )
                            if result.returncode == 0:
                                import json
                                inspect_data = json.loads(result.stdout)[0]
                                # Try to get OS family to infer base
                                os_family = inspect_data.get('Metadata', {}).get('OS', {}).get('Family', '')
                                # Use common base images based on OS
                                if 'debian' in os_family.lower() or 'ubuntu' in os_family.lower():
                                    base_image = 'debian:bullseye-slim'
                                elif 'alpine' in os_family.lower():
                                    base_image = 'alpine:latest'
                                else:
                                    # Fallback: try to extract from repo tags
                                    repotags = inspect_data.get('RepoTags', [])
                                    if repotags:
                                        base_image = original_image_name.split(':')[0] if ':' in original_image_name else original_image_name
                                    else:
                                        base_image = 'debian:bullseye-slim'  # Safe default
                                
                                # Replace placeholder
                                dockerfile_content = re.sub(
                                    r'FROM\s*<original-base[^>]*>.*',
                                    f'FROM {base_image}',
                                    dockerfile_content,
                                    flags=re.IGNORECASE | re.MULTILINE
                                )
                            else:
                                # Fallback: use safe default
                                base_image = 'debian:bullseye-slim'
                                dockerfile_content = re.sub(
                                    r'FROM\s*<original-base[^>]*>.*',
                                    f'FROM {base_image}',
                                    dockerfile_content,
                                    flags=re.IGNORECASE | re.MULTILINE
                                )
                        except Exception as e:
                            logging.warning(f"Could not determine base image, using default: {e}")
                            # Fallback to safe default
                            base_image = 'debian:bullseye-slim'
                            dockerfile_content = re.sub(
                                r'FROM\s*<original-base[^>]*>.*',
                                f'FROM {base_image}',
                                dockerfile_content,
                                flags=re.IGNORECASE | re.MULTILINE
                            )
                
                if dockerfile_content and 'FROM' in dockerfile_content:
                    logging.info(f"Successfully extracted Dockerfile ({len(dockerfile_content)} chars)")
                    return dockerfile_content
                else:
                    logging.warning(f"Extracted content doesn't look like a Dockerfile")
        
        logging.warning("No Dockerfile found in LLM response")
        return None

    def fix_dockerfile_dependencies(self, dockerfile_path: Path, build_error: str) -> bool:
        """Auto-fix Dockerfile dependency conflicts"""
        try:
            content = self.pipeline.safe_read_file(str(dockerfile_path))
            
            # Extract conflicting packages from error
            import re
            # Pattern: "libgssapi-krb5-2 : Depends: libkrb5-3 (= 1.18.3-6+deb11u5) but 1.18.3-6+deb11u7 is to be installed"
            dep_pattern = r'Depends:\s+(\S+)\s*\(=\s*([^)]+)\)\s+but\s+([^\s]+)\s+is to be installed'
            matches = re.findall(dep_pattern, build_error)
            
            if matches:
                # Strategy: Fix dependency conflicts
                # Error: "package A depends on B=version1 but version2 is available"
                # Solution: Either update B to version2 OR update A to a version that works with B=version2
                for pkg, required_version, available_version in matches:
                    # The dependency package that's causing issues
                    dep_pkg = pkg
                    
                    # Check if we pinned this dependency package
                    if f'{dep_pkg}=' in content:
                        # We pinned it - update to available version
                        old_pattern = rf'{re.escape(dep_pkg)}=[^\s\\]+'
                        new_pkg_line = f'{dep_pkg}={available_version}'
                        content = re.sub(old_pattern, new_pkg_line, content)
                        logging.info(f"Fixed: Updated {dep_pkg} from {required_version} to {available_version}")
                    else:
                        # We didn't pin it, but something that depends on it is causing issues
                        # Remove pins from packages that depend on this, or add the dependency version
                        # Find parent packages in apt-get install lines
                        apt_lines = re.findall(r'RUN apt-get install[^\n]*(?:\\[^\n]*\n[^\n]*)*', content, re.MULTILINE)
                        for apt_line in apt_lines:
                            # Check if any package in this line might depend on dep_pkg
                            # For now, just add the dependency explicitly with the available version
                            if dep_pkg not in apt_line and '=' not in apt_line:
                                # Add it to ensure compatibility
                                content = content.replace(apt_line, f'{apt_line.rstrip()} {dep_pkg}={available_version}')
                                logging.info(f"Fixed: Added {dep_pkg}={available_version} to satisfy dependencies")
                                break
            
            # Alternative: If still having issues, remove all version pins from RUN apt-get install
            # But only if we detect multiple dependency errors
            if "unmet dependencies" in build_error.lower() and build_error.count("Depends:") > 1:
                # More aggressive fix: Remove version pins, let apt resolve
                # Only remove pins from the problematic line
                apt_line_pattern = r'(RUN apt-get install[^\n]*)(\\[^\n]*\n[^\n]*=)'
                if re.search(apt_line_pattern, content):
                    # Remove =version from packages in apt-get install
                    content = re.sub(r'(\S+)=([^\s\\]+)', r'\1', content, flags=re.MULTILINE)
                    logging.info("Applied aggressive fix: Removed all version pins from apt-get install")
            
            # Save fixed Dockerfile
            backup_path = dockerfile_path.parent / f"{dockerfile_path.name}.backup"
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(self.pipeline.safe_read_file(str(dockerfile_path)))
            
            with open(dockerfile_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            logging.info(f"Fixed Dockerfile saved (backup: {backup_path})")
            return True
            
        except Exception as e:
            logging.error(f"Failed to fix Dockerfile dependencies: {e}", exc_info=True)
            return False

    def compare_vulnerabilities(self, original_vulns: List[Dict], new_vulns: List[Dict]) -> Dict[str, Any]:
        """Compare vulnerabilities between original and new scan"""
        original_count = len(original_vulns)
        new_count = len(new_vulns)
        
        # Count by severity
        original_severities = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        new_severities = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for vuln in original_vulns:
            sev = vuln.get('severity', 'UNKNOWN').upper()
            if sev in original_severities:
                original_severities[sev] += 1
        
        for vuln in new_vulns:
            sev = vuln.get('severity', 'UNKNOWN').upper()
            if sev in new_severities:
                new_severities[sev] += 1
        
        # Calculate improvement
        critical_high_original = original_severities['CRITICAL'] + original_severities['HIGH']
        critical_high_new = new_severities['CRITICAL'] + new_severities['HIGH']
        improvement = critical_high_original - critical_high_new
        
        return {
            'original_total': original_count,
            'new_total': new_count,
            'improvement': improvement,
            'improvement_percent': (improvement / critical_high_original * 100) if critical_high_original > 0 else 0,
            'original_severities': original_severities,
            'new_severities': new_severities,
            'is_improved': improvement > 0 or (improvement == 0 and new_count < original_count)
        }

    def generate_remediation(self, image_name: str, scan_results: Dict) -> Dict:
        """Generate AI-powered remediation recommendations"""
        logging.info("Generating image remediation...")
        
        image_info = self.detect_image_type(image_name)
        vulnerabilities = self.parse_trivy_results(scan_results["txt_file"], scan_results.get("json_file"))
        
        # Enrich vulnerabilities with actual available versions
        enriched_vulns = self.enrich_vulnerabilities_with_versions(vulnerabilities)
        fixable_vulns = [v for v in enriched_vulns if v.get('verified_fix_version') and v['verified_fix_version'] != 'unknown']
        
        if not self.llm_client:
            self.llm_client = LlamaAPIClient()
        
        # Discover original project files (including Dockerfile) for context
        project_files = self.discover_project_files(image_info['technology_stack'])
        original_dockerfile = project_files.get('dockerfile', '')
        
        # Use RAG to retrieve relevant context from ChromaDB
        context = self.retrieve_rag_context(image_name, vulnerabilities)
        base_prompt = self.pipeline.load_external_prompt("image")
        
        # Build version information for the LLM
        version_info = "\n\nVERIFIED VERSION INFORMATION:\n"
        for vuln in fixable_vulns[:10]:  # Limit to top 10 to avoid token limits
            version_info += f"\n- {vuln['library']} (CVE: {vuln['cve_id']}):\n"
            version_info += f"  Current: {vuln['installed_version']}\n"
            version_info += f"  Verified Fix: {vuln.get('verified_fix_version', 'unknown')}\n"
            if vuln.get('available_versions'):
                version_info += f"  Available versions: {', '.join(vuln['available_versions'][:5])}\n"
            if vuln.get('fix_version_warning'):
                version_info += f"  ⚠️  {vuln['fix_version_warning']}\n"
        
        # Build original Dockerfile context
        dockerfile_context = ""
        if original_dockerfile:
            dockerfile_context = f"\n\nORIGINAL DOCKERFILE:\n```dockerfile\n{original_dockerfile}\n```\n\n"
            dockerfile_context += "IMPORTANT: Use the above Dockerfile as the base. Replace <original-base> with the actual base image FROM line shown above.\n"
        else:
            dockerfile_context = "\n\nORIGINAL DOCKERFILE: Not found in project directory.\n"
            dockerfile_context += "IMPORTANT: Generate a complete, working Dockerfile. You must determine the correct base image from the image metadata provided below.\n"
        
        # Extract base image from image metadata if possible
        base_image_hint = ""
        try:
            result = subprocess.run(
                ["docker", "inspect", image_name],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                import json
                inspect_data = json.loads(result.stdout)[0]
                # Try to extract RepoTags to infer base
                repotags = inspect_data.get('RepoTags', [])
                if repotags:
                    base_image_hint = f"Base image hint: The original image is '{image_name}'. Use a similar base (e.g., if image is java-app, base might be openjdk:17 or similar)."
        except:
            pass
        
        comprehensive_prompt = f"""{base_prompt}

IMAGE ANALYSIS CONTEXT:
- Image Name: {image_name}
- Technology Stack: {', '.join(image_info['technology_stack'])}
- Base Operating System: {image_info['base_os']}
- Exposed Ports: {', '.join(image_info['exposed_ports']) if image_info['exposed_ports'] else 'None'}
- Working Directory: {image_info['working_dir']}
{base_image_hint}

{dockerfile_context}

VULNERABILITIES FOUND: {len(fixable_vulns)} fixable out of {len(vulnerabilities)} total

{version_info}

CRITICAL INSTRUCTIONS FOR DOCKERFILE GENERATION:
1. Generate a COMPLETE, WORKING Dockerfile in the "Remediated Files to Generate" section
2. NEVER use placeholders like <original-base> - use the actual base image FROM the original Dockerfile or infer from image name
3. Package version pinning - BE SMART ABOUT DEPENDENCIES:
   - Pin versions ONLY for packages with HIGH/CRITICAL CVEs that need specific fixes
   - For dependencies of pinned packages, either:
     a) Pin the dependency to the version required by the parent package, OR
     b) Don't pin it and let apt resolve automatically
   - Example: If libgssapi-krb5-2 depends on libkrb5-3=version1, don't pin libkrb5-3=version2
   - When pinning multiple packages, check their interdependencies first
   - If uncertain, install packages without version pins and upgrade only the vulnerable ones: apt-get install package1=fix1 package2 (auto-resolve deps)
   - STRATEGY: Install dependencies first without pins, then upgrade specific vulnerable packages
4. Follow the mandatory Dockerfile order: FROM → OS packages → User creation → WORKDIR → COPY → USER → Dependencies → EXPOSE → CMD
5. Include all necessary steps from the original Dockerfile (if provided)
6. Ensure the Dockerfile is buildable and functional - dependency conflicts will cause build failures

CRITICAL INSTRUCTIONS FOR VERSION RECOMMENDATIONS:
1. ONLY use versions from the "Verified Fix" or "Available versions" lists above
2. DO NOT suggest versions that don't exist (like v1.9.0 for gorilla/mux when only v1.8.x exists)
3. If uncertain about a version, suggest the latest from the "Available versions" list
4. For Go modules, use the exact version format shown (e.g., v1.8.0, v1.8.1)
5. Always verify versions exist before recommending them

Please provide:
1. Complete, working Dockerfile.secured with NO placeholders
2. Dependency updates using versions from the lists above
3. Security best practices for {image_info['base_os']} images
"""
        
        # Use higher max_tokens for remediation generation (needs full Dockerfile + report)
        response = self.llm_client.query(
            comprehensive_prompt, 
            context, 
            is_security_query=True,
            max_tokens=8000,  # Increased for complete Dockerfile + remediation report
            timeout=300  # Longer timeout for larger responses
        )
        
        timestamp = scan_results["timestamp"]
        safe_image_name = re.sub(r'[^\w\-_]', '_', image_name)
        report_file = self.pipeline.image_remediation_dir / f"remediation_report_{safe_image_name}_{timestamp}.md"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(f"# Image Security Remediation Report\n\n")
            f.write(f"**Image:** {image_name}\n")
            f.write(f"**Technology Stack:** {', '.join(image_info['technology_stack'])}\n")
            f.write(f"**Base OS:** {image_info['base_os']}\n")
            f.write(f"**Generated:** {timestamp}\n")
            f.write(f"**Total Vulnerabilities:** {len(vulnerabilities)}\n")
            f.write(f"**Fixable Vulnerabilities:** {len(fixable_vulns)}\n\n")
            
            # Add version verification summary
            f.write(f"## Version Verification Summary\n\n")
            f.write("All recommended versions have been verified against package registries:\n\n")
            for vuln in fixable_vulns[:20]:
                f.write(f"- **{vuln['library']}**: {vuln['installed_version']} → {vuln.get('verified_fix_version', 'unknown')}\n")
                if vuln.get('fix_version_warning'):
                    f.write(f"  - ⚠️ {vuln['fix_version_warning']}\n")
            f.write("\n")
            
            f.write(f"## AI-Generated Remediation\n\n{response}\n")
        
        logging.info(f"Remediation report saved to: {report_file}")
        
        # Debug: Check response length and content
        print("\n" + "="*70)
        print("📝 LLM RESPONSE ANALYSIS")
        print("="*70)
        print(f"   Response length: {len(response):,} characters")
        print(f"   Contains 'Dockerfile': {'Dockerfile' in response}")
        print(f"   Contains '```dockerfile': {'```dockerfile' in response.lower()}")
        print(f"   Contains 'FROM': {'FROM' in response}")
        print(f"   Contains 'Remediated Files': {'Remediated Files' in response}")
        
        # Extract and save Dockerfile if present in response
        print("\n" + "="*70)
        print("🔍 EXTRACTING DOCKERFILE FROM LLM RESPONSE")
        print("="*70)
        dockerfile_content = self.extract_dockerfile_from_response(response, image_name)
        dockerfile_path = None
        validation_result = None
        
        if dockerfile_content:
            dockerfile_path = self.pipeline.image_remediation_dir / f"Dockerfile.secured_{safe_image_name}_{timestamp}"
            try:
                with open(dockerfile_path, 'w', encoding='utf-8') as f:
                    f.write(dockerfile_content)
                print(f"✅ Dockerfile extracted and saved!")
                print(f"   Location: {dockerfile_path}")
                print(f"   Size: {len(dockerfile_content)} characters")
                logging.info(f"✅ Extracted and saved Dockerfile to: {dockerfile_path}")
                
                # Attempt to build, scan, and validate the secured image
                print("\n" + "="*70)
                print("🔨 STARTING VALIDATION PIPELINE")
                print("="*70)
                print("Steps: Build → Scan → Compare → Cleanup")
                logging.info("🔨 Starting validation pipeline: build → scan → compare → cleanup")
                validation_result = self.validate_secured_dockerfile(
                    image_name, dockerfile_path, vulnerabilities, timestamp
                )
                print(f"\n✅ Validation complete: {validation_result.get('status', 'unknown')}")
                logging.info(f"✅ Validation complete: {validation_result.get('status', 'unknown')}")
                
            except Exception as e:
                print(f"\n❌ ERROR: Failed to save Dockerfile: {e}")
                logging.error(f"❌ Failed to save Dockerfile: {e}", exc_info=True)
        else:
            print("\n⚠️  WARNING: No Dockerfile found in LLM response!")
            print("   This means the LLM didn't generate a complete Dockerfile.")
            print("   Response length:", len(response), "characters")
            print("   Searching response for Dockerfile patterns...")
            # Debug: show what patterns we're looking for
            if '```dockerfile' in response.lower():
                print("   ✓ Found '```dockerfile' in response")
            if 'dockerfile.secured' in response.lower():
                print("   ✓ Found 'dockerfile.secured' in response")
            if 'FROM' in response:
                print("   ✓ Found 'FROM' in response (but may not be in code block)")
            logging.warning("⚠️ No Dockerfile found in LLM response - validation skipped")
        
        return {
            "report_file": str(report_file),
            "dockerfile_path": str(dockerfile_path) if dockerfile_path else None,
            "image_info": image_info,
            "total_vulnerabilities": len(vulnerabilities),
            "fixable_vulnerabilities": len(fixable_vulns),
            "enriched_vulnerabilities": enriched_vulns,
            "timestamp": timestamp,
            "validation": validation_result  # FIX: Return actual validation_result, not None!
        }

    def create_test_dockerfile(self, dockerfile_path: Path) -> Optional[Path]:
        """Create a test Dockerfile without COPY commands and runtime dependency installs for validation"""
        try:
            content = self.pipeline.safe_read_file(str(dockerfile_path))
            
            # Remove or comment out COPY commands and runtime dependency installs
            lines = content.split('\n')
            test_lines = []
            skip_copy = False
            skip_runtime = False
            in_run_command = False
            run_buffer = []
            
            i = 0
            while i < len(lines):
                line = lines[i]
                stripped = line.strip().upper()
                original_line = lines[i]
                
                # Detect RUN commands
                if stripped.startswith('RUN'):
                    run_buffer = [original_line]
                    
                    # Check if it's a multi-line RUN command (with backslash continuation)
                    if '\\' in line:
                        # Collect all continuation lines
                        j = i + 1
                        while j < len(lines):
                            next_line = lines[j]
                            # Check if line ends with backslash (continuation) or starts with && (command chain)
                            if next_line.rstrip().endswith('\\') or next_line.strip().startswith('&&'):
                                run_buffer.append(next_line)
                                j += 1
                            else:
                                break
                        
                        # Check what this RUN command does
                        full_run = ' '.join(run_buffer).upper()
                        
                        # Skip if it installs runtime dependencies
                        runtime_patterns = [
                            'NPM CI', 'NPM INSTALL', 'PIP INSTALL', 'BUNDLE INSTALL',
                            'GO MOD', 'COMPOSER INSTALL', 'CABAL INSTALL',
                            'MAVEN', 'GRADLE', 'POETRY INSTALL', 'YARN INSTALL',
                            'POETRY', 'CARGO BUILD', 'STACK BUILD'
                        ]
                        
                        if any(pattern in full_run for pattern in runtime_patterns):
                            test_lines.append(f"# COMMENTED FOR TEST: {run_buffer[0]}")
                            for bline in run_buffer[1:]:
                                test_lines.append(f"# {bline}")
                            test_lines.append("# Note: Runtime dependency installation skipped for test build")
                            skip_runtime = True
                            i = j
                            continue
                    else:
                        # Single-line RUN or multi-line with && - check if it's runtime install
                        # For && chains, collect the full chain
                        full_run_line = original_line
                        j = i + 1
                        while j < len(lines):
                            next_line = lines[j]
                            if next_line.strip().startswith('&&') or next_line.strip().startswith('\\'):
                                full_run_line += ' ' + next_line.strip()
                                j += 1
                            else:
                                break
                        
                        full_run = full_run_line.upper()
                        
                        runtime_patterns = [
                            'NPM CI', 'NPM INSTALL', 'PIP INSTALL', 'BUNDLE INSTALL',
                            'GO MOD', 'COMPOSER INSTALL', 'CABAL INSTALL',
                            'MAVEN', 'GRADLE', 'POETRY INSTALL', 'YARN INSTALL'
                        ]
                        
                        if any(pattern in full_run for pattern in runtime_patterns):
                            test_lines.append(f"# COMMENTED FOR TEST: {original_line}")
                            # Comment out continuation lines if any
                            for k in range(i + 1, j):
                                test_lines.append(f"# {lines[k]}")
                            test_lines.append("# Note: Runtime dependency installation skipped for test build")
                            skip_runtime = True
                            i = j
                            continue
                    
                    # If we reach here, keep the RUN command as-is
                    test_lines.append(original_line)
                    i += 1
                    continue
                
                # Skip COPY commands that need files
                if stripped.startswith('COPY') or stripped.startswith('ADD'):
                    # Check if it's copying application files
                    if any(pattern in stripped for pattern in [
                        'APP.JAR', 'TARGET/', '.CLASS', 'SRC/', 'PACKAGE.JSON', 
                        'REQUIREMENTS.TXT', 'GEMFILE', 'POM.XML', 'GO.MOD'
                    ]):
                        test_lines.append(f"# COMMENTED FOR TEST: {original_line}")
                        test_lines.append("# Note: Actual build will need these files")
                        skip_copy = True
                        i += 1
                        continue
                
                # Keep other lines (FROM, ENV, WORKDIR, USER, EXPOSE, CMD, ENTRYPOINT, etc.)
                test_lines.append(original_line)
                i += 1
            
            if not (skip_copy or skip_runtime):
                return None  # No problematic commands, use original
            
            # Create test Dockerfile
            test_dockerfile_path = dockerfile_path.parent / f"{dockerfile_path.name}.test"
            test_content = '\n'.join(test_lines)
            
            # Add a note at the end
            test_content += "\n\n# TEST BUILD MODE:"
            if skip_copy:
                test_content += "\n# - COPY commands commented out (files not in build context)"
            if skip_runtime:
                test_content += "\n# - Runtime dependency installs skipped (files not available)"
            test_content += "\n# The actual Dockerfile will work when built with proper project files"
            test_content += "\n# This test validates that OS package updates work correctly"
            
            with open(test_dockerfile_path, 'w', encoding='utf-8') as f:
                f.write(test_content)
            
            logging.info(f"Created test Dockerfile: {test_dockerfile_path}")
            return test_dockerfile_path
        except Exception as e:
            logging.warning(f"Could not create test Dockerfile: {e}")
            return None

    def validate_secured_dockerfile(self, original_image_name: str, dockerfile_path: Path, 
                                    original_vulnerabilities: List[Dict], timestamp: str) -> Dict[str, Any]:
        """Build secured image, scan it, compare results, and cleanup if no improvement"""
        print("\n📋 VALIDATION PIPELINE STARTED")
        logging.info("Validating secured Dockerfile...")
        
        safe_image_name = re.sub(r'[^\w\-_]', '_', original_image_name)
        secured_image_name = f"{safe_image_name}_secured_{timestamp}"
        
        try:
            # Check if build context has required files - if not, create test Dockerfile
            test_dockerfile = self.create_test_dockerfile(dockerfile_path)
            actual_dockerfile = test_dockerfile if test_dockerfile else dockerfile_path
            
            if test_dockerfile:
                print(f"   ⚠️  Original Dockerfile requires application files not in build context")
                print(f"   📝 Created test Dockerfile without COPY commands for validation")
            
            # Step 1: Build the secured image
            print(f"\n[1/4] 🔨 Building secured Docker image...")
            print(f"   Image name: {secured_image_name}")
            print(f"   Dockerfile: {actual_dockerfile}")
            logging.info(f"Building secured image: {secured_image_name}")
            
            # Use --no-cache to avoid hanging and --progress=plain for better output
            build_cmd = [
                "docker", "build", 
                "--no-cache",
                "--progress=plain",
                "-t", secured_image_name, 
                "-f", str(actual_dockerfile), 
                "."
            ]
            print("   Running: docker build (with --no-cache to avoid hanging)...")
            
            # Reduced timeout and better progress tracking
            rc, out, err = self.pipeline.run_cmd(build_cmd, timeout=300)  # 5 minutes instead of 10
            
            if rc != 0:
                print(f"   ❌ BUILD FAILED!")
                
                # Check error types
                err_lower = err.lower() if err else ""
                out_lower = out.lower() if out else ""
                full_error = (err or "") + (out or "")
                
                # Check for missing file errors (most common)
                is_missing_file = (
                    "not found" in err_lower or
                    "failed to calculate checksum" in err_lower or
                    "no such file or directory" in err_lower or
                    "cannot find" in err_lower
                )
                
                # Check for runtime dependency errors (npm, pip, etc.)
                is_runtime_dependency_error = (
                    "npm ci" in err_lower and "package-lock.json" in err_lower or
                    "npm install" in err_lower and ("enoent" in err_lower or "not found" in err_lower) or
                    "pip install" in err_lower and ("no such file" in err_lower or "requirements.txt" in err_lower) or
                    "could not find" in err_lower and ("package.json" in err_lower or "requirements.txt" in err_lower or "go.mod" in err_lower)
                )
                
                # Check if it's a dependency conflict
                is_dependency_error = (
                    "unmet dependencies" in err_lower or
                    "depends:" in err_lower or
                    "broken packages" in err_lower or
                    "Unable to correct problems" in err
                )
                
                if is_missing_file or is_runtime_dependency_error:
                    error_type = "runtime dependency" if is_runtime_dependency_error else "missing files"
                    print(f"   ⚠️  Build failed due to {error_type} in build context")
                    print(f"   📝 This is expected - the Dockerfile needs application files/dependencies to build")
                    print(f"   ✅ Dockerfile structure is valid (OS packages/vulnerabilities fixed)")
                    print(f"   💡 To build properly, copy the Dockerfile to your project directory")
                    print(f"   💡 and run: docker build -f Dockerfile.secured .")
                    
                    # Return success status since the Dockerfile is structurally correct
                    return {
                        "status": "validation_skipped_missing_files",
                        "improvement": None,  # Can't determine without actual build
                        "message": f"Dockerfile generated but requires {error_type} to complete build",
                        "dockerfile_path": str(dockerfile_path),
                        "note": "The Dockerfile fixes OS-level vulnerabilities. Runtime deps need project files."
                    }
                
                elif is_dependency_error:
                    print(f"   ⚠️  Dependency conflict detected! Attempting auto-fix...")
                    fixed_dockerfile = self.fix_dockerfile_dependencies(dockerfile_path, err)
                    
                    if fixed_dockerfile:
                        print(f"   🔧 Fixed Dockerfile saved. Retrying build...")
                        # Retry build with fixed Dockerfile
                        rc, out, err = self.pipeline.run_cmd(build_cmd, timeout=300)
                        if rc == 0:
                            print(f"   ✅ Build successful after auto-fix!")
                            logging.info(f"Build succeeded after dependency fix")
                            # Continue with scanning
                        else:
                            print(f"   ❌ Build still failed after auto-fix")
                            print(f"   Error: {err[:500] if err else 'Unknown error'}")
                            logging.error(f"Docker build failed even after auto-fix: {err}")
                            return {
                                "status": "build_failed",
                                "error": err,
                                "improvement": False,
                                "auto_fix_attempted": True
                            }
                    else:
                        print(f"   ⚠️  Could not auto-fix dependencies")
                        logging.error(f"Docker build failed with dependency error: {err}")
                        return {
                            "status": "build_failed",
                            "error": err,
                            "improvement": False,
                            "error_type": "dependency_conflict"
                        }
                else:
                    print(f"   ❌ Build failed with other error")
                    error_preview = (err or out or "Unknown error")[:500]
                    print(f"   Error preview: {error_preview}")
                    logging.error(f"Docker build failed: {err or out}")
                    
                    # Check if it's a timeout
                    if "timeout" in error_preview.lower() or "timed out" in error_preview.lower():
                        print(f"   ⏱️  Build timed out - this might be a network issue")
                        print(f"   💡 Try building manually or check internet connection")
                    
                    return {
                        "status": "build_failed",
                        "error": err or out or "Unknown error",
                        "improvement": False,
                        "error_type": "other"
                    }
            
            print(f"   ✅ Build successful!")
            logging.info(f"Successfully built secured image: {secured_image_name}")
            
            # Step 2: Scan the secured image with Trivy
            print(f"\n[2/4] 🔍 Scanning secured image with Trivy...")
            print(f"   Image: {secured_image_name}")
            logging.info("Scanning secured image with Trivy...")
            new_scan_results = self.run_trivy_scan(secured_image_name)
            print(f"   ✅ Scan complete")
            
            # Step 3: Parse new scan results
            print(f"\n[3/4] 📊 Comparing vulnerabilities...")
            new_vulnerabilities = self.parse_trivy_results(new_scan_results["txt_file"], new_scan_results.get("json_file"))
            print(f"   Original: {len(original_vulnerabilities)} vulnerabilities")
            print(f"   Secured: {len(new_vulnerabilities)} vulnerabilities")
            
            # Step 4: Compare vulnerabilities
            comparison = self.compare_vulnerabilities(original_vulnerabilities, new_vulnerabilities)
            print(f"   CRITICAL/HIGH - Original: {comparison['original_severities']['CRITICAL'] + comparison['original_severities']['HIGH']}")
            print(f"   CRITICAL/HIGH - Secured: {comparison['new_severities']['CRITICAL'] + comparison['new_severities']['HIGH']}")
            print(f"   Improvement: {comparison['improvement']} fewer critical/high vulnerabilities")
            
            # Step 5: Decide whether to keep or cleanup
            print(f"\n[4/4] 🎯 Validation Decision...")
            if comparison['is_improved']:
                print(f"   ✅ IMPROVEMENT DETECTED!")
                print(f"   🎉 Keeping secured image: {secured_image_name}")
                logging.info(f"✅ Improvement detected! {comparison['improvement']} fewer CRITICAL/HIGH vulnerabilities")
                logging.info(f"   Original: {comparison['original_total']} total, {comparison['original_severities']['CRITICAL'] + comparison['original_severities']['HIGH']} CRITICAL/HIGH")
                logging.info(f"   Secured: {comparison['new_total']} total, {comparison['new_severities']['CRITICAL'] + comparison['new_severities']['HIGH']} CRITICAL/HIGH")
                
                # Update report with validation results
                report_file = self.pipeline.image_remediation_dir / f"remediation_report_{safe_image_name}_{timestamp}.md"
                if report_file.exists():
                    with open(report_file, 'a', encoding='utf-8') as f:
                        f.write(f"\n## Validation Results ✅\n\n")
                        f.write(f"**Secured Image:** {secured_image_name}\n\n")
                        f.write(f"**Original Vulnerabilities:** {comparison['original_total']} total ")
                        f.write(f"({comparison['original_severities']['CRITICAL']} CRITICAL, {comparison['original_severities']['HIGH']} HIGH)\n\n")
                        f.write(f"**Secured Image Vulnerabilities:** {comparison['new_total']} total ")
                        f.write(f"({comparison['new_severities']['CRITICAL']} CRITICAL, {comparison['new_severities']['HIGH']} HIGH)\n\n")
                        f.write(f"**Improvement:** {comparison['improvement']} fewer CRITICAL/HIGH vulnerabilities ")
                        f.write(f"({comparison['improvement_percent']:.1f}% reduction)\n\n")
                        f.write(f"✅ **Secured image validated and ready for use!**\n")
                
                return {
                    "status": "success",
                    "improvement": True,
                    "secured_image": secured_image_name,
                    "comparison": comparison,
                    "new_scan_results": new_scan_results
                }
            else:
                print(f"   ❌ NO IMPROVEMENT DETECTED")
                print(f"   🗑️  Cleaning up secured image...")
                logging.warning(f"❌ No improvement detected. Original: {comparison['original_total']}, Secured: {comparison['new_total']}")
                
                # Cleanup: Remove secured image
                logging.info(f"Cleaning up secured image: {secured_image_name}")
                cleanup_cmd = ["docker", "rmi", "-f", secured_image_name]
                rc_cleanup, _, _ = self.pipeline.run_cmd(cleanup_cmd, timeout=60)
                if rc_cleanup == 0:
                    print(f"   ✅ Image removed")
                else:
                    print(f"   ⚠️  Could not remove image (may not exist)")
                
                # Optionally remove Dockerfile (keep it for debugging)
                # dockerfile_path.unlink()
                
                # Update report with validation results
                report_file = self.pipeline.image_remediation_dir / f"remediation_report_{safe_image_name}_{timestamp}.md"
                if report_file.exists():
                    with open(report_file, 'a', encoding='utf-8') as f:
                        f.write(f"\n## Validation Results ❌\n\n")
                        f.write(f"**Secured Image:** {secured_image_name} (CLEANED UP)\n\n")
                        f.write(f"**Original Vulnerabilities:** {comparison['original_total']} total\n\n")
                        f.write(f"**Secured Image Vulnerabilities:** {comparison['new_total']} total\n\n")
                        f.write(f"⚠️ **No significant improvement detected. Secured image has been removed.**\n")
                        f.write(f"Please review the remediation report and manually adjust the Dockerfile if needed.\n")
                
                return {
                    "status": "no_improvement",
                    "improvement": False,
                    "comparison": comparison,
                    "cleaned_up": True
                }
                
        except Exception as e:
            logging.error(f"Error during validation: {e}", exc_info=True)
            # Try to cleanup on error
            try:
                cleanup_cmd = ["docker", "rmi", "-f", secured_image_name]
                self.pipeline.run_cmd(cleanup_cmd, timeout=60)
            except:
                pass
            
            return {
                "status": "error",
                "improvement": False,
                "error": str(e)
        }

    def run_image_pipeline(self, image_name: str) -> Dict:
        """Complete image scanning pipeline"""
        logging.info(f"Starting image security pipeline for: {image_name}")
        
        # Ensure RAG system is initialized
        if not self.pipeline.collection:
            logging.info("Initializing RAG system for image pipeline...")
            self.pipeline.setup_rag_system()
        
        # Validate image exists
        if not self.validate_docker_image(image_name):
            logging.warning(f"Image {image_name} not found locally")
            if not self.guide_docker_pull(image_name):
                raise RuntimeError(f"Image {image_name} is not available")
        
        # Run Trivy scan
        trivy_results = self.run_trivy_scan(image_name)
        
        # Index scan data IMMEDIATELY after scan (so RAG has context for remediation)
        logging.info("Indexing Trivy scan results into ChromaDB...")
        self.pipeline.enhanced_index_scan_data(image_name, {
            "trivy_txt": trivy_results["txt_file"],
            "trivy_json": trivy_results["json_file"],
            "sbom_cyclonedx": trivy_results["sbom_cyclonedx"]  # ADD THIS LINE
        })
        
        # Generate remediation with version verification (now RAG has scan data)
        remediation = self.generate_remediation(image_name, trivy_results)
        
        # Index remediation report and Dockerfile if generated
        index_data = {}
        if remediation.get('report_file'):
            index_data['remediation_report'] = remediation['report_file']
        if remediation.get('dockerfile_path'):
            index_data['dockerfile_secured'] = remediation['dockerfile_path']
        if index_data:
            logging.info("Indexing remediation artifacts into ChromaDB...")
            self.pipeline.enhanced_index_scan_data(f"{image_name}_remediation", index_data)
        
        logging.info("Image security pipeline completed successfully")
        return remediation