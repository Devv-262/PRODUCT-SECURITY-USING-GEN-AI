#!/usr/bin/env python3

"""
Pod Security Analysis Module - UPDATED WITH CLUSTER SUPPORT
Handles Kubernetes manifest scanning and remediation
Can scan local YAML files OR extract from running cluster
"""

import subprocess
import datetime
import logging
import re
import json
import tempfile
import yaml
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from difflib import unified_diff

from common import EnhancedSecurityPipeline, LlamaAPIClient


class PodSecurityAnalyzer:
    """Kubernetes manifest security scanning - supports local files AND cluster resources"""

    def __init__(self, pipeline: EnhancedSecurityPipeline):
        self.pipeline = pipeline
        self.llm_client = None
        
        self.scan_outputs_dir = self.pipeline.scans_dir / "kubernetes_scans"
        self.scan_outputs_dir.mkdir(parents=True, exist_ok=True)
        
        logging.info("PodSecurityAnalyzer initialized")

    def list_k8s_pods(self, namespace: str = None, all_namespaces: bool = False) -> List[Dict[str, str]]:
        """List running pods in cluster with proper indexing"""
        cmd = ["kubectl", "get", "pods", "-o", "wide"]
        if all_namespaces:
            cmd.append("--all-namespaces")
        elif namespace:
            cmd.extend(["-n", namespace])

        rc, out, err = self.pipeline.run_cmd(cmd)
        pods = []
        
        if rc == 0 and out:
            lines = out.strip().splitlines()
            if len(lines) >= 2:
                header = lines[0]
                has_namespace = all_namespaces or "NAMESPACE" in header
                
                for idx, line in enumerate(lines[1:], start=1):
                    parts = line.split()
                    if not parts:
                        continue
                    
                    try:
                        if has_namespace:
                            pod_data = {
                                "index": idx,
                                "namespace": parts[0] if len(parts) > 0 else "unknown",
                                "name": parts[1] if len(parts) > 1 else "unknown",
                                "ready": parts[2] if len(parts) > 2 else "0/0",
                                "status": parts[3] if len(parts) > 3 else "Unknown",
                                "restarts": parts[4] if len(parts) > 4 else "0",
                                "age": parts[5] if len(parts) > 5 else "unknown",
                                "ip": parts[6] if len(parts) > 6 else "",
                                "node": parts[7] if len(parts) > 7 else ""
                            }
                        else:
                            pod_data = {
                                "index": idx,
                                "namespace": namespace or "default",
                                "name": parts[0] if len(parts) > 0 else "unknown",
                                "ready": parts[1] if len(parts) > 1 else "0/0",
                                "status": parts[2] if len(parts) > 2 else "Unknown",
                                "restarts": parts[3] if len(parts) > 3 else "0",
                                "age": parts[4] if len(parts) > 4 else "unknown",
                                "ip": parts[5] if len(parts) > 5 else "",
                                "node": parts[6] if len(parts) > 6 else ""
                            }
                        pods.append(pod_data)
                    except Exception as e:
                        logging.debug(f"Error parsing pod line: {e}")
                        continue
        
        return pods

    def list_k8s_resources(self, all_namespaces: bool = True) -> List[Dict[str, str]]:
        """List all Kubernetes resources that can be scanned"""
        resources = []
        resource_types = [
            ("deployments", "Deployment"),
            ("daemonsets", "DaemonSet"),
            ("statefulsets", "StatefulSet"),
            ("pods", "Pod"),
            ("services", "Service"),
            ("configmaps", "ConfigMap"),
            ("secrets", "Secret"),
            ("ingresses", "Ingress"),
            ("networkpolicies", "NetworkPolicy")
        ]
        
        idx = 1
        for resource_type, kind in resource_types:
            cmd = ["kubectl", "get", resource_type, "-o", "json"]
            if all_namespaces:
                cmd.append("--all-namespaces")
            
            rc, out, err = self.pipeline.run_cmd(cmd, timeout=30)
            
            if rc == 0 and out:
                try:
                    data = json.loads(out)
                    items = data.get("items", [])
                    
                    for item in items:
                        metadata = item.get("metadata", {})
                        name = metadata.get("name", "unknown")
                        namespace = metadata.get("namespace", "default")
                        
                        resources.append({
                            "index": idx,
                            "kind": kind,
                            "name": name,
                            "namespace": namespace,
                            "resource_type": resource_type
                        })
                        idx += 1
                except json.JSONDecodeError as e:
                    logging.debug(f"Failed to parse {resource_type}: {e}")
        
        return resources

    def extract_resource_manifest(self, kind: str, name: str, namespace: str, resource_type: str) -> Optional[str]:
        """Extract YAML manifest for a specific resource from cluster"""
        cmd = ["kubectl", "get", resource_type, name, "-n", namespace, "-o", "yaml"]
        
        rc, out, err = self.pipeline.run_cmd(cmd, timeout=30)
        
        if rc == 0 and out:
            # Clean up kubectl metadata that causes validation issues
            try:
                docs = list(yaml.safe_load_all(out))
                cleaned_docs = []
                
                for doc in docs:
                    if doc and isinstance(doc, dict):
                        # Remove kubectl-specific metadata
                        if "metadata" in doc:
                            metadata = doc["metadata"]
                            # Remove managedFields (huge and not needed for scanning)
                            metadata.pop("managedFields", None)
                            # Remove runtime fields
                            metadata.pop("resourceVersion", None)
                            metadata.pop("uid", None)
                            metadata.pop("selfLink", None)
                            metadata.pop("creationTimestamp", None)
                        
                        # Remove status section (runtime data)
                        doc.pop("status", None)
                        
                        cleaned_docs.append(doc)
                
                # Convert back to YAML
                cleaned_yaml = yaml.dump_all(cleaned_docs, default_flow_style=False, sort_keys=False)
                return cleaned_yaml
            except Exception as e:
                logging.warning(f"Failed to clean manifest for {kind}/{name}: {e}")
                return out
        else:
            logging.error(f"Failed to extract {kind}/{name} from namespace {namespace}")
            return None

    def pretty_print_pods(self, pods: List[Dict], title: str = "Kubernetes Pods"):
        """Pretty print pods with indexing"""
        if not pods:
            print(f"\n❌ No {title.lower()} found.")
            return
        
        print(f"\n{'='*100}")
        print(f"📷 {title.upper()} ({len(pods)} found)")
        print(f"{'='*100}")
        print(f"{'IDX':<5} {'NAMESPACE':<20} {'POD NAME':<40} {'STATUS':<12} {'AGE':<10}")
        print(f"{'-'*100}")
        
        for pod in pods:
            idx = pod.get('index', 0)
            namespace = pod.get('namespace', 'default')[:19]
            name = pod.get('name', 'unknown')[:39]
            status = pod.get('status', 'Unknown')[:11]
            age = pod.get('age', 'unknown')[:9]
            
            print(f"{idx:<5} {namespace:<20} {name:<40} {status:<12} {age:<10}")
        
        print(f"{'='*100}\n")

    def pretty_print_resources(self, resources: List[Dict], title: str = "Kubernetes Resources"):
        """Pretty print Kubernetes resources"""
        if not resources:
            print(f"\n❌ No {title.lower()} found.")
            return
        
        print(f"\n{'='*120}")
        print(f"☸️ {title.upper()} ({len(resources)} found)")
        print(f"{'='*120}")
        print(f"{'IDX':<5} {'KIND':<20} {'NAME':<50} {'NAMESPACE':<30}")
        print(f"{'-'*120}")
        
        for resource in resources:
            idx = resource.get('index', 0)
            kind = resource.get('kind', 'Unknown')[:19]
            name = resource.get('name', 'unknown')[:49]
            namespace = resource.get('namespace', 'default')[:29]
            
            print(f"{idx:<5} {kind:<20} {name:<50} {namespace:<30}")
        
        print(f"{'='*120}\n")

    def run_kubescore_scan(self, yaml_file: str) -> Tuple[str, str]:
        """Run kube-score and save output"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = Path(yaml_file).stem
        output_file = self.scan_outputs_dir / f"kubescore_{filename}_{timestamp}.txt"
        
        logging.info(f"🔍 Running kube-score on {Path(yaml_file).name}...")
        
        try:
            result = subprocess.run(
                ["kube-score", "score", yaml_file],
                capture_output=True,
                text=True,
                timeout=120,
                encoding='utf-8',
                errors='replace'
            )
            
            output = result.stdout or result.stderr or "No output from kube-score"
            
            with open(output_file, 'w', encoding='utf-8', errors='replace') as f:
                f.write(output)
            
            logging.info(f"✅ kube-score output saved: {output_file}")
            return output, str(output_file)
            
        except FileNotFoundError:
            msg = "Error: kube-score not found. Install: brew install kube-score"
            logging.warning(msg)
            return msg, ""
        except Exception as e:
            msg = f"kube-score error: {e}"
            logging.error(msg)
            return msg, ""

    def run_kubescape_scan(self, yaml_file: str) -> Tuple[str, str]:
        """Run kubescape and save output"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = Path(yaml_file).stem
        output_file = self.scan_outputs_dir / f"kubescape_{filename}_{timestamp}.json"
        
        logging.info(f"🔍 Running kubescape on {Path(yaml_file).name}...")
        
        try:
            result = subprocess.run(
                ["kubescape", "scan", yaml_file, "--format", "json", "--output", str(output_file)],
                capture_output=True,
                text=True,
                timeout=120,
                encoding='utf-8',
                errors='replace'
            )
            
            if output_file.exists():
                with open(output_file, 'r', encoding='utf-8', errors='replace') as f:
                    json_output = f.read()
                logging.info(f"✅ kubescape output saved: {output_file}")
                return json_output, str(output_file)
            else:
                result = subprocess.run(
                    ["kubescape", "scan", yaml_file, "--format", "pretty-printer"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    encoding='utf-8',
                    errors='replace'
                )
                output = result.stdout or result.stderr or "No output"
                
                txt_file = self.scan_outputs_dir / f"kubescape_{filename}_{timestamp}.txt"
                with open(txt_file, 'w', encoding='utf-8', errors='replace') as f:
                    f.write(output)
                
                logging.info(f"✅ kubescape output saved: {txt_file}")
                return output, str(txt_file)
                
        except FileNotFoundError:
            msg = "Error: kubescape not found. Install from https://github.com/kubescape/kubescape"
            logging.warning(msg)
            return msg, ""
        except Exception as e:
            msg = f"kubescape error: {e}"
            logging.error(msg)
            return msg, ""
        
    def run_kyverno_scan(self, yaml_file: str) -> Tuple[str, str]:
        """Run kyverno and save output"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = Path(yaml_file).stem
        output_file = self.scan_outputs_dir / f"kyverno_{filename}_{timestamp}.txt"
        
        logging.info(f"🔍 Running kyverno on {Path(yaml_file).name}...")
        
        try:
            subprocess.run(
                ["kyverno", "version"],
                capture_output=True,
                check=True,
                encoding='utf-8',
                errors='replace'
            )
            
            result = subprocess.run(
                ["kyverno", "apply", "--resource", yaml_file],
                capture_output=True,
                text=True,
                timeout=120,
                encoding='utf-8',
                errors='replace'
            )
            
            output = result.stdout or result.stderr or "Kyverno scan completed"
            
            with open(output_file, 'w', encoding='utf-8', errors='replace') as f:
                f.write(output)
            
            logging.info(f"✅ kyverno output saved: {output_file}")
            return output, str(output_file)
            
        except FileNotFoundError:
            msg = "Error: kyverno CLI not found. Install from https://github.com/kyverno/kyverno/releases"
            logging.warning(msg)
            return msg, ""
        except subprocess.TimeoutExpired:
            msg = "Kyverno scan timed out"
            logging.error(msg)
            return msg, ""
        except Exception as e:
            msg = f"Kyverno scan error: {e}"
            logging.error(msg)
            return msg, ""

    def validate_yaml_syntax(self, yaml_content: str) -> Tuple[bool, str]:
        """Validate YAML syntax and K8s structure"""
        try:
            docs = list(yaml.safe_load_all(yaml_content))
            
            if not docs or all(doc is None for doc in docs):
                return False, "Empty YAML or no valid documents"
            
            for i, doc in enumerate(docs):
                if doc is None:
                    continue
                    
                if not isinstance(doc, dict):
                    return False, f"Document {i+1} is not a valid object"
                
                if 'apiVersion' not in doc:
                    return False, f"Document {i+1} missing apiVersion"
                
                if 'kind' not in doc:
                    return False, f"Document {i+1} missing kind"
                
                if 'metadata' not in doc:
                    return False, f"Document {i+1} missing metadata"
                
                if not isinstance(doc['metadata'], dict) or 'name' not in doc['metadata']:
                    return False, f"Document {i+1} missing metadata.name"
            
            return True, "Valid YAML"
            
        except yaml.YAMLError as e:
            return False, f"YAML syntax error: {str(e)}"
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    def run_pod_pipeline(self, yaml_files: List[str] = None, from_cluster: bool = False, 
                         resource_selections: List[Dict] = None) -> Dict:
        """
        MAIN METHOD: Run complete pod security pipeline
        Can scan local YAML files OR extract from cluster
        
        Args:
            yaml_files: List of local YAML file paths
            from_cluster: If True, extract manifests from cluster using resource_selections
            resource_selections: List of resource dicts with kind, name, namespace, resource_type
        """
        try:
            # Handle cluster extraction mode
            if from_cluster and resource_selections:
                logging.info(f"🔄 Extracting {len(resource_selections)} manifests from cluster...")
                
                # Create temp directory for extracted manifests
                temp_manifest_dir = self.pipeline.output_dir / "temp_cluster_manifests"
                temp_manifest_dir.mkdir(parents=True, exist_ok=True)
                
                extracted_files = []
                
                for resource in resource_selections:
                    kind = resource.get('kind', 'Unknown')
                    name = resource.get('name', 'unknown')
                    namespace = resource.get('namespace', 'default')
                    resource_type = resource.get('resource_type', 'pods')
                    
                    logging.info(f"  Extracting {kind}/{name} from {namespace}...")
                    
                    manifest_yaml = self.extract_resource_manifest(kind, name, namespace, resource_type)
                    
                    if manifest_yaml:
                        # Save to temp file
                        safe_name = f"{kind}_{name}_{namespace}".replace("/", "_").replace(":", "_")
                        temp_file = temp_manifest_dir / f"{safe_name}.yaml"
                        
                        with open(temp_file, 'w', encoding='utf-8') as f:
                            f.write(manifest_yaml)
                        
                        extracted_files.append(str(temp_file))
                        logging.info(f"    ✅ Saved to {temp_file.name}")
                    else:
                        logging.warning(f"    ⚠️ Failed to extract {kind}/{name}")
                
                if not extracted_files:
                    return {
                        "error": "Failed to extract any manifests from cluster",
                        "files_analyzed": 0,
                        "total_issues": 0
                    }
                
                # Use extracted files for scanning
                yaml_files = extracted_files
                logging.info(f"✅ Extracted {len(extracted_files)} manifests from cluster")
            
            # Validate input
            if not yaml_files:
                return {
                    "error": "No manifest files provided",
                    "files_analyzed": 0,
                    "total_issues": 0
                }
            
            logging.info(f"🚀 Starting Kubernetes security pipeline...")
            logging.info(f"📋 Files to scan: {len(yaml_files)}")
            
            for i, f in enumerate(yaml_files, 1):
                logging.info(f"   {i}. {Path(f).name}")
            
            # Validate all files exist first
            valid_files = []
            for yaml_file in yaml_files:
                if not Path(yaml_file).exists():
                    logging.error(f"❌ File not found: {yaml_file}")
                    continue
                valid_files.append(yaml_file)
            
            if not valid_files:
                return {
                    "error": "None of the specified files exist",
                    "files_analyzed": 0,
                    "total_issues": 0
                }
            
            logging.info(f"✅ Validated {len(valid_files)} file(s)")
            
            # Generate remediation for ONLY these files
            remediation_result = self.generate_pod_remediation(valid_files)
            
            remediation_result['timestamp'] = datetime.datetime.now().isoformat()
            remediation_result['from_cluster'] = from_cluster
            
            return remediation_result
            
        except Exception as e:
            logging.error(f"❌ Pipeline error: {e}", exc_info=True)
            return {
                "error": str(e),
                "files_analyzed": 0,
                "total_issues": 0
            }

    def generate_pod_remediation(self, yaml_files: List[str]) -> Dict:
        """
        Generate pod security remediation
        ONLY processes files in yaml_files list
        """
        logging.info(f"📋 Generating remediation for {len(yaml_files)} file(s)...")

        yaml_scan_results = {}
        total_issues = 0
        scan_outputs = {}

        # Phase 1: Scan ONLY the specified files
        for yaml_file in yaml_files:
            logging.info(f"📋 Scanning {Path(yaml_file).name}...")
            
            yaml_content = self.pipeline.safe_read_file(yaml_file)
            
            if not yaml_content:
                logging.warning(f"⚠️ Empty or unreadable file: {yaml_file}")
                continue
            
            # Run all three scanners
            kubescore_result, kubescore_file = self.run_kubescore_scan(yaml_file)
            kubescape_result, kubescape_file = self.run_kubescape_scan(yaml_file)
            kyverno_result, kyverno_file = self.run_kyverno_scan(yaml_file)

            # Count issues
            issues = (
                kubescore_result.count("CRITICAL") + 
                kubescore_result.count("WARNING") +
                kubescape_result.count("failed") + 
                kubescape_result.count("Failed") +
                kyverno_result.count("fail") + 
                kyverno_result.count("FAIL")
            )
            
            total_issues += issues

            yaml_scan_results[yaml_file] = {
                "content": yaml_content,
                "kubescore": kubescore_result,
                "kubescape": kubescape_result,
                "kyverno": kyverno_result,
                "issues": issues,
                "kubescore_file": kubescore_file,
                "kubescape_file": kubescape_file,
                "kyverno_file": kyverno_file
            }
            
            scan_outputs[yaml_file] = {
                "kubescore_file": kubescore_file,
                "kubescape_file": kubescape_file,
                "kyverno_file": kyverno_file
            }
            
            logging.info(f"   ✅ Found {issues} issues")

        if not yaml_scan_results:
            return {
                "error": "No valid scan results",
                "files_analyzed": 0,
                "total_issues": 0
            }

        # Phase 2: Index scan data for RAG
        logging.info("💾 Indexing scan data for RAG...")
        self._index_scan_data_for_rag(yaml_scan_results)

        # Phase 3: Generate remediation with LLM
        if not self.llm_client:
            self.llm_client = LlamaAPIClient()

        # Load external prompt
        prompt = self.load_optimized_prompt()
        
        # Build context
        combined_context = self._build_llm_context(yaml_scan_results, yaml_files, total_issues)
        
        context_size = len(prompt) + len(combined_context)
        logging.info(f"📊 Context size: {context_size:,} characters")
        logging.info(f"📊 Prompt size: {len(prompt):,} characters")
        logging.info(f"📊 Scan context size: {len(combined_context):,} characters")
        
        logging.info("🤖 Querying LLM for remediation...")
        response = self.llm_client.query(
            prompt, 
            combined_context, 
            temperature=0.1,
            max_tokens=16000,
            timeout=300
        )

        # Phase 4: Extract improved manifests ONLY if critical issues found
        improved_manifests = {}
        
        # Only generate if there are critical security issues
        critical_count = sum(
            results['kubescore'].count('CRITICAL') + 
            results['kubescape'].count('failed')
            for results in yaml_scan_results.values()
        )
        
        if critical_count > 0:
            logging.info(f"🔒 {critical_count} critical issues found, extracting improved manifests...")
            improved_manifests = self.extract_improved_yaml(response, yaml_files)
        else:
            logging.info("✅ No critical issues found, skipping manifest generation")

        # Phase 5: Rescan if improved manifests were generated
        rescan_results = {}
        if improved_manifests:
            rescan_results = self.rescan_improved_manifests(improved_manifests)

        # Phase 6: Generate diffs
        diffs = {}
        for original_file, improved_file in improved_manifests.items():
            diff = self.generate_yaml_diff(original_file, improved_file)
            diffs[original_file] = diff

        # Phase 7: Generate report
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.pipeline.pod_remediation_dir / f"pod_remediation_report_{timestamp}.md"

        self._generate_comprehensive_report(
            report_file, timestamp, yaml_files, total_issues, 
            response, improved_manifests, rescan_results, diffs, scan_outputs
        )

        return {
            "report_file": str(report_file),
            "improved_manifests": improved_manifests,
            "total_issues": total_issues,
            "files_analyzed": len(yaml_files),
            "scan_results": yaml_scan_results,
            "rescan_results": rescan_results,
            "diffs": diffs,
            "scan_outputs": scan_outputs,
            "timestamp": timestamp
        }

    def _index_scan_data_for_rag(self, yaml_scan_results: Dict):
        """Index scan content into ChromaDB with proper chunking"""
        if not self.pipeline.collection:
            logging.warning("⚠️ RAG system not initialized. Skipping indexing.")
            return
        
        try:
            documents = []
            metadatas = []
            ids = []
            doc_id = 0
            
            for yaml_file, results in yaml_scan_results.items():
                file_name = Path(yaml_file).name
                
                # Parse YAML metadata
                try:
                    docs_list = list(yaml.safe_load_all(results['content']))
                    resource_info = []
                    
                    for doc in docs_list:
                        if doc and isinstance(doc, dict):
                            resource_info.append({
                                'kind': doc.get('kind', 'Unknown'),
                                'name': doc.get('metadata', {}).get('name', 'Unknown'),
                                'namespace': doc.get('metadata', {}).get('namespace', 'default')
                            })
                except Exception as e:
                    logging.debug(f"Could not parse YAML metadata: {e}")
                    resource_info = []
                
                resource_summary = ', '.join([f"{r['kind']}/{r['name']}" for r in resource_info])
                
                # Chunk and index kube-score findings
                kubescore_chunks = self._chunk_scan_output(
                    results['kubescore'],
                    chunk_size=2000,
                    overlap=200
                )
                
                for i, chunk in enumerate(kubescore_chunks):
                    content = f"""KUBERNETES MANIFEST: {file_name}
RESOURCES: {resource_summary}
SCAN TOOL: kube-score
CHUNK: {i+1}/{len(kubescore_chunks)}

FINDINGS:
{chunk}

ORIGINAL YAML:
{results['content'][:1000]}
"""
                    documents.append(content)
                    metadatas.append({
                        "scan_type": "kubernetes",
                        "tool": "kube-score",
                        "file_name": file_name,
                        "yaml_file": yaml_file,
                        "chunk": i
                    })
                    ids.append(f"k8s_kubescore_{doc_id}_{i}")
                
                # Chunk and index kubescape findings
                kubescape_chunks = self._chunk_scan_output(
                    results['kubescape'],
                    chunk_size=2000,
                    overlap=200
                )
                
                for i, chunk in enumerate(kubescape_chunks):
                    content = f"""KUBERNETES MANIFEST: {file_name}
RESOURCES: {resource_summary}
SCAN TOOL: kubescape (NIST Framework)
CHUNK: {i+1}/{len(kubescape_chunks)}

FINDINGS:
{chunk}

ORIGINAL YAML:
{results['content'][:1000]}
"""
                    documents.append(content)
                    metadatas.append({
                        "scan_type": "kubernetes",
                        "tool": "kubescape",
                        "file_name": file_name,
                        "yaml_file": yaml_file,
                        "chunk": i
                    })
                    ids.append(f"k8s_kubescape_{doc_id}_{i}")
                
                # Chunk and index kyverno findings
                kyverno_chunks = self._chunk_scan_output(
                    results['kyverno'],
                    chunk_size=2000,
                    overlap=200
                )
                
                for i, chunk in enumerate(kyverno_chunks):
                    content = f"""KUBERNETES MANIFEST: {file_name}
RESOURCES: {resource_summary}
SCAN TOOL: kyverno (Policy Validation)
CHUNK: {i+1}/{len(kyverno_chunks)}

FINDINGS:
{chunk}

ORIGINAL YAML:
{results['content'][:1000]}
"""
                    documents.append(content)
                    metadatas.append({
                        "scan_type": "kubernetes",
                        "tool": "kyverno",
                        "file_name": file_name,
                        "yaml_file": yaml_file,
                        "chunk": i
                    })
                    ids.append(f"k8s_kyverno_{doc_id}_{i}")
                
                doc_id += 1
            
            # Add all documents to ChromaDB
            if documents:
                self.pipeline.collection.add(
                    documents=documents,
                    metadatas=metadatas,
                    ids=ids
                )
                logging.info(f"✅ Indexed {len(documents)} scan document chunks")
            else:
                logging.warning("⚠️ No documents to index")
                
        except Exception as e:
            logging.error(f"❌ Failed to index scan data: {e}", exc_info=True)

    def _chunk_scan_output(self, text: str, chunk_size: int = 2000, overlap: int = 200) -> List[str]:
        """Split scan output into overlapping chunks"""
        if not text:
            return []
        
        if len(text) <= chunk_size:
            return [text]
        
        chunks = []
        start = 0
        
        while start < len(text):
            end = start + chunk_size
            
            if end < len(text):
                newline_pos = text.rfind('\n', start, end)
                if newline_pos > start:
                    end = newline_pos
            
            chunks.append(text[start:end])
            start = max(end - overlap, end)
        
        return chunks

    def _build_llm_context(self, yaml_scan_results: Dict, yaml_files: List[str], total_issues: int) -> str:
        """Build optimized context for LLM"""
        
        context_parts = [
            "=" * 80,
            "KUBERNETES SECURITY ANALYSIS - SCAN RESULTS",
            "=" * 80,
            f"\nFILES ANALYZED: {len(yaml_files)}",
            f"TOTAL ISSUES DETECTED: {total_issues}",
            f"SCANNING TOOLS: kube-score, kubescape (NIST), kyverno (Policy)",
            "\n" + "=" * 80 + "\n"
        ]
        
        for yaml_file, results in yaml_scan_results.items():
            file_name = Path(yaml_file).name
            
            context_parts.extend([
                "\n" + "─" * 80,
                f"FILE: {file_name}",
                "─" * 80,
                f"ISSUES: {results['issues']} total",
                ""
            ])
            
            # Parse resource metadata
            try:
                docs = list(yaml.safe_load_all(results['content']))
                for doc in docs:
                    if doc and isinstance(doc, dict):
                        context_parts.append(
                            f"RESOURCE: {doc.get('kind', 'Unknown')}/{doc.get('metadata', {}).get('name', 'Unknown')}"
                        )
            except Exception:
                pass
            
            context_parts.extend([
                "",
                "KUBE-SCORE FINDINGS:",
                "-" * 40,
                results['kubescore'][:3000],
                "",
                "KUBESCAPE FINDINGS (NIST Framework):",
                "-" * 40,
                results['kubescape'][:3000],
                "",
                "KYVERNO FINDINGS (Policy Validation):",
                "-" * 40,
                results['kyverno'][:3000],
                "",
                "ORIGINAL YAML:",
                "-" * 40,
                results['content'],
                ""
            ])
        
        context_parts.append("\n" + "=" * 80)
        
        return "\n".join(context_parts)

    def load_optimized_prompt(self) -> str:
        """Load prompt from external file or return default"""
        custom_prompt = self.pipeline.load_external_prompt("pod")
        
        if custom_prompt:
            logging.info("✅ Using external prompt from prompt_pod_security.txt")
            return custom_prompt
        
        logging.warning("⚠️ External prompt not found, using default")
        
        # Default fallback prompt
        return """You are a Senior Kubernetes Security Engineer specializing in remediating security findings from kube-score, kubescape, and kyverno.

CRITICAL: Generate COMPLETE, VALID, DEPLOYABLE Kubernetes manifests with NO placeholders, NO truncation, and proper 2-space YAML indentation.

Analyze the scan results and provide PRODUCTION-READY secured manifests ONLY for files with CRITICAL security issues."""

    def extract_improved_yaml(self, llm_response: str, original_files: List[str]) -> Dict[str, str]:
        """Extract improved YAML manifests from LLM response"""
        improved_manifests = {}
        
        yaml_pattern = r'```yaml\s+(.*?)```'
        yaml_blocks = re.findall(yaml_pattern, llm_response, re.DOTALL)
        
        if not yaml_blocks:
            logging.warning("⚠️ No YAML blocks found in LLM response")
            return improved_manifests
        
        logging.info(f"📦 Found {len(yaml_blocks)} YAML blocks in response")
        
        for i, yaml_content in enumerate(yaml_blocks):
            is_valid, validation_msg = self.validate_yaml_syntax(yaml_content)
            
            if not is_valid:
                logging.warning(f"❌ Invalid YAML in block {i+1}: {validation_msg}")
                continue
            
            original_file = None
            
            try:
                docs = list(yaml.safe_load_all(yaml_content))
                for doc in docs:
                    if doc and isinstance(doc, dict):
                        resource_name = doc.get('metadata', {}).get('name', '')
                        
                        for orig_file in original_files:
                            orig_content = self.pipeline.safe_read_file(orig_file)
                            if resource_name in orig_content:
                                original_file = orig_file
                                break
                    if original_file:
                        break
            except Exception as e:
                logging.debug(f"Could not parse YAML for matching: {e}")
            
            if not original_file and i < len(original_files):
                original_file = original_files[i]
            
            if not original_file:
                logging.warning(f"⚠️ Could not match YAML block {i+1} to original file")
                continue
            
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            original_name = Path(original_file).stem
            improved_file = self.pipeline.safer_manifests_dir / f"{original_name}_improved_{timestamp}.yaml"
            
            try:
                with open(improved_file, 'w', encoding='utf-8', errors='replace') as f:
                    f.write(yaml_content)
                
                improved_manifests[original_file] = str(improved_file)
                logging.info(f"✅ Saved improved manifest: {improved_file}")
            except Exception as e:
                logging.error(f"❌ Failed to save improved manifest: {e}")
        
        return improved_manifests

    def rescan_improved_manifests(self, improved_files: Dict[str, str]) -> Dict[str, Dict]:
        """Rescan improved manifests to verify fixes"""
        logging.info("🔄 Rescanning improved manifests...")
        
        rescan_results = {}
        
        for original_file, improved_file in improved_files.items():
            logging.info(f"Scanning improved: {Path(original_file).name}")
            
            yaml_content = self.pipeline.safe_read_file(improved_file)
            is_valid, validation_msg = self.validate_yaml_syntax(yaml_content)
            
            if not is_valid:
                logging.error(f"❌ Invalid YAML: {validation_msg}")
                rescan_results[original_file] = {
                    "valid": False,
                    "error": validation_msg,
                    "kubescore": "Skipped - invalid YAML",
                    "kubescape": "Skipped - invalid YAML",
                    "kyverno": "Skipped - invalid YAML"
                }
                continue
            
            # Run all three scans
            kubescore_result, kubescore_file = self.run_kubescore_scan(improved_file)
            kubescape_result, kubescape_file = self.run_kubescape_scan(improved_file)
            kyverno_result, kyverno_file = self.run_kyverno_scan(improved_file)
            
            # Count remaining issues
            issues = (
                kubescore_result.count("CRITICAL") + 
                kubescore_result.count("WARNING") +
                kubescape_result.count("failed") + 
                kubescape_result.count("Failed") +
                kyverno_result.count("fail") + 
                kyverno_result.count("FAIL")
            )
            
            rescan_results[original_file] = {
                "valid": True,
                "issues": issues,
                "kubescore": kubescore_result[:500],
                "kubescape": kubescape_result[:500],
                "kyverno": kyverno_result[:500],
                "kubescore_file": kubescore_file,
                "kubescape_file": kubescape_file,
                "kyverno_file": kyverno_file
            }
            
            logging.info(f"  ✅ Remaining issues: {issues}")
        
        return rescan_results

    def generate_yaml_diff(self, original_file: str, improved_file: str) -> str:
        """Generate unified diff between original and improved YAML"""
        try:
            with open(original_file, 'r', encoding='utf-8', errors='replace') as f:
                original_lines = f.readlines()
            
            with open(improved_file, 'r', encoding='utf-8', errors='replace') as f:
                improved_lines = f.readlines()
            
            diff = unified_diff(
                original_lines,
                improved_lines,
                fromfile=f"original/{Path(original_file).name}",
                tofile=f"improved/{Path(improved_file).name}",
                lineterm=''
            )
            
            return '\n'.join(diff)
        except Exception as e:
            logging.error(f"Error generating diff: {e}")
            return f"Error generating diff: {e}"

    def _generate_comprehensive_report(self, report_file: Path, timestamp: str, 
                                      yaml_files: List[str], total_issues: int,
                                      llm_response: str, improved_manifests: Dict[str, str],
                                      rescan_results: Dict, diffs: Dict, scan_outputs: Dict):
        """Generate comprehensive markdown report"""
        
        with open(report_file, 'w', encoding='utf-8', errors='replace') as f:
            # Header
            f.write("# Kubernetes Security Remediation Report\n\n")
            f.write(f"**Generated:** {timestamp}\n")
            f.write(f"**Files Analyzed:** {len(yaml_files)}\n")
            f.write(f"**Total Issues Found:** {total_issues}\n")
            f.write(f"**Improved Manifests Generated:** {len(improved_manifests)}\n\n")
            
            # Files scanned
            f.write("## 📋 Files Scanned\n\n")
            for i, yaml_file in enumerate(yaml_files, 1):
                f.write(f"{i}. `{Path(yaml_file).name}`\n")
            f.write("\n")
            
            # Scan output locations
            f.write("## 📂 Scan Output Files\n\n")
            for yaml_file, outputs in scan_outputs.items():
                f.write(f"### {Path(yaml_file).name}\n\n")
                if outputs.get('kubescore_file'):
                    f.write(f"- **kube-score:** `{outputs['kubescore_file']}`\n")
                if outputs.get('kubescape_file'):
                    f.write(f"- **kubescape:** `{outputs['kubescape_file']}`\n")
                if outputs.get('kyverno_file'):
                    f.write(f"- **kyverno:** `{outputs['kyverno_file']}`\n")
                f.write("\n")
            
            # Executive Summary
            f.write("## 📊 Executive Summary\n\n")
            f.write("| Metric | Value |\n")
            f.write("|--------|-------|\n")
            f.write(f"| Files Scanned | {len(yaml_files)} |\n")
            f.write(f"| Issues Detected | {total_issues} |\n")
            f.write(f"| Manifests Remediated | {len(improved_manifests)} |\n")
            
            if rescan_results:
                total_remaining = sum(r.get('issues', 0) for r in rescan_results.values() if r.get('valid'))
                improvement_pct = ((total_issues - total_remaining) / total_issues * 100) if total_issues > 0 else 0
                f.write(f"| Remaining Issues | {total_remaining} |\n")
                f.write(f"| Improvement | {improvement_pct:.1f}% |\n")
            
            f.write("\n")
            
            # LLM Analysis
            f.write("## 🔍 Security Analysis & Recommendations\n\n")
            f.write(llm_response)
            f.write("\n\n")
            
            # Changes Summary
            if diffs and improved_manifests:
                f.write("## 📝 Changes Made (YAML Diff)\n\n")
                
                for original_file, improved_file in improved_manifests.items():
                    f.write(f"### {Path(original_file).name}\n\n")
                    
                    if original_file in rescan_results:
                        rescan = rescan_results[original_file]
                        if rescan.get('valid'):
                            f.write(f"**Status:** ✅ Valid YAML\n")
                            f.write(f"**Remaining Issues:** {rescan.get('issues', 0)}\n\n")
                        else:
                            f.write(f"**Status:** ❌ Invalid YAML\n")
                            f.write(f"**Error:** {rescan.get('error', 'Unknown')}\n\n")
                    
                    if original_file in diffs:
                        f.write("```diff\n")
                        f.write(diffs[original_file])
                        f.write("\n```\n\n")
                    
                    f.write(f"**Improved file:** `{improved_file}`\n\n")
                    f.write("---\n\n")
            
            # Deployment Instructions
            if improved_manifests:
                f.write("## 🚀 Deployment Instructions\n\n")
                f.write("```bash\n")
                f.write("# Validate manifests\n")
                for improved_file in improved_manifests.values():
                    f.write(f"kubectl apply --dry-run=client -f {improved_file}\n")
                f.write("\n# Deploy to cluster\n")
                for improved_file in improved_manifests.values():
                    f.write(f"kubectl apply -f {improved_file}\n")
                f.write("```\n\n")
            
            f.write("---\n")
            f.write(f"*Report generated by Enhanced Security Pipeline on {timestamp}*\n")
        
        logging.info(f"📄 Report saved: {report_file}")


if __name__ == "__main__":
    from common import EnhancedSecurityPipeline
    
    print("Testing pod_security.py...")
    pipeline = EnhancedSecurityPipeline()
    analyzer = PodSecurityAnalyzer(pipeline)
    print(f"✓ PodSecurityAnalyzer initialized")
    
    # Test cluster connectivity
    print("\nTesting Kubernetes cluster connectivity...")
    resources = analyzer.list_k8s_resources(all_namespaces=True)
    if resources:
        print(f"✓ Found {len(resources)} resources in cluster")
        analyzer.pretty_print_resources(resources[:10], "Sample Cluster Resources")
    else:
        print("⚠️ No resources found (cluster may not be running)")
    
    print("\nAll components loaded successfully!")