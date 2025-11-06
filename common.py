import os
import sys
import subprocess
import logging
import json
import requests
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
import chromadb
from chromadb.utils import embedding_functions

# Configure logging with UTF-8 encoding
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_pipeline.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ],
    force=True
)

# Ensure UTF-8 encoding for stdout/stderr
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if sys.stderr.encoding != 'utf-8':
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


class LlamaAPIClient:
    """Client for LLM API integration (OpenAI, Groq, Llama API)"""

    _GROQ_ENDPOINTS = [
        "https://api.groq.com/openai/v1/chat/completions",
        "https://api.groq.com/v1/chat/completions",
    ]
    
    _OPENAI_ENDPOINT = "https://api.openai.com/v1/chat/completions"

    def __init__(self, api_key: str = None, model: str = "openai/gpt-oss-120b", verbose: bool = True):
        self.verbose = verbose  # Set this FIRST before calling _load_api_key
        self.model = model
        self.provider = "unknown"
        self.base_url = None
        self.api_key = api_key or self._load_api_key()

        if self.api_key:
            if self.api_key.startswith("sk-"):
                self.provider = "openai"
                self.base_url = self._OPENAI_ENDPOINT
            elif self.api_key.startswith("gsk_"):
                self.provider = "groq"
                self.base_url = self._GROQ_ENDPOINTS[0]
            else:
                self.provider = "llama-api"
                self.base_url = "https://api.llama-api.com/chat/completions"
        
        if self.verbose:
            logging.info(f"LLM client initialized (provider={self.provider}, model={self.model})")
        
    def _load_api_key(self) -> Optional[str]:
        """Load API key from file or environment"""
        api_key_file = Path("API_KEY.txt")
        if api_key_file.exists():
            try:
                with open(api_key_file, 'r', encoding='utf-8') as f:
                    key = f.read().strip()
                    if key:
                        if getattr(self, 'verbose', True):  # Safe check
                            logging.info("API key loaded from API_KEY.txt")
                        return key
            except Exception as e:
                logging.warning(f"Could not read API_KEY.txt: {e}")

        env_key = os.getenv("OPENAI_API_KEY") or os.getenv("LLAMA_API_KEY")
        if env_key:
            if getattr(self, 'verbose', True):  # Safe check
                logging.info(f"API key loaded from environment variable")
            return env_key

        logging.warning("No API key found. Create API_KEY.txt or set OPENAI_API_KEY/LLAMA_API_KEY")
        return None

    def _try_groq_request(self, headers: Dict[str, str], payload: Dict[str, Any], timeout: int):
        """Attempt to send request to Groq endpoints"""
        last_exc = None
        for endpoint in self._GROQ_ENDPOINTS:
            try:
                r = requests.post(endpoint, headers=headers, json=payload, timeout=timeout)
                return r, endpoint
            except Exception as e:
                last_exc = e
                if self.verbose:
                    logging.debug(f"Groq endpoint {endpoint} failed: {e}")
                continue
        raise last_exc or RuntimeError("All Groq endpoints failed")

    def query(self, prompt: str, context: str = "", is_security_query: bool = True,
              temperature: float = 0.3, max_tokens: int = 16000, timeout: int = 300) -> str:
        """Query the configured LLM provider"""
        if not self.api_key:
            return "Error: API key not configured. Please create API_KEY.txt or set OPENAI_API_KEY/LLAMA_API_KEY."

        full_prompt = f"{prompt}\n\nCONTEXT:\n{context}" if context else prompt
        
        # Only log detailed stats if verbose mode is enabled
        if self.verbose:
            prompt_chars = len(prompt)
            context_chars = len(context)
            total_chars = len(full_prompt)
            
            logging.info(f"📊 LLM Query Details:")
            logging.info(f"   Model: {self.model}")
            logging.info(f"   Provider: {self.provider}")
            logging.info(f"   Prompt size: {prompt_chars:,} characters")
            logging.info(f"   Context size: {context_chars:,} characters")
            logging.info(f"   Total input: {total_chars:,} characters")
            logging.info(f"   Max tokens: {max_tokens:,}")
            
            estimated_input_tokens = total_chars // 4
            logging.info(f"   Estimated input tokens: ~{estimated_input_tokens:,}")
            
            if estimated_input_tokens > 100000:
                logging.warning(f"⚠️ Large context size may exceed model limits!")

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        messages = [
            {"role": "system", "content": "You are a senior cybersecurity expert and DevSecOps engineer."},
            {"role": "user", "content": full_prompt}
        ]

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }
        
        # Special handling for GPT-OSS-120B
        if "gpt-oss" in self.model.lower():
            if self.verbose:
                logging.info(f"🔧 Using GPT-OSS-120B optimized settings...")
            payload["temperature"] = min(temperature, 0.7)
        
        import datetime
        if self.verbose:
            logging.info(f"🚀 Sending request to {self.provider} API ({self.model})...")
        start_time = datetime.datetime.now()

        try:
            if self.provider == "groq":
                response, endpoint_used = self._try_groq_request(headers, payload, timeout)
            elif self.provider == "openai":
                endpoint_used = self.base_url
                response = requests.post(endpoint_used, headers=headers, json=payload, timeout=timeout)
            else:
                endpoint_used = self.base_url
                response = requests.post(endpoint_used, headers=headers, json=payload, timeout=timeout)
        except Exception as e:
            logging.error(f"Request failed: {e}")
            return f"Error: {e}"
        
        elapsed = (datetime.datetime.now() - start_time).total_seconds()
        if self.verbose:
            logging.info(f"✅ Response received in {elapsed:.2f} seconds")

        try:
            if response.status_code != 200:
                logging.error(f"API Error: {response.status_code} - {response.text}")
                return f"API Error {response.status_code}: {response.text}"

            result = response.json()
        except Exception as e:
            logging.error(f"Failed to parse API response JSON: {e}")
            return f"Error parsing API response: {e}"

        try:
            if isinstance(result, dict) and "choices" in result:
                choice = result["choices"][0]
                if isinstance(choice, dict):
                    if "message" in choice and "content" in choice["message"]:
                        response_text = choice["message"]["content"]
                        
                        if self.verbose:
                            logging.info(f"📊 Response size: {len(response_text):,} characters")
                            
                            # Log token usage if available
                            if "usage" in result:
                                usage = result["usage"]
                                logging.info(f"📊 Token usage:")
                                logging.info(f"   Prompt tokens: {usage.get('prompt_tokens', 'N/A'):,}")
                                logging.info(f"   Completion tokens: {usage.get('completion_tokens', 'N/A'):,}")
                                logging.info(f"   Total tokens: {usage.get('total_tokens', 'N/A'):,}")
                        
                        return response_text
                    if "text" in choice:
                        return choice["text"]
                    if "content" in choice:
                        return choice["content"]

            if "output" in result:
                out = result["output"]
                if isinstance(out, str):
                    return out

            if isinstance(result, dict):
                for v in result.values():
                    if isinstance(v, str) and v.strip():
                        return v

            logging.warning("Could not extract text from response, using fallback")
            return json.dumps(result)[:5000]

        except Exception as e:
            logging.error(f"Error extracting response text: {e}")
            return f"Error extracting response: {e}"

class SecurityKnowledgeBase:
    """Security knowledge base for CVE information"""

    def __init__(self):
        self.cve_cache: Dict[str, str] = {}

    def get_cve_context(self, query: str) -> str:
        """Pull CVE IDs from query and return context"""
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        cves = re.findall(cve_pattern, (query or "").upper())

        if not cves:
            return ""

        context_lines = ["\n\nCVE KNOWLEDGE BASE:"]
        for cve_id in cves:
            if cve_id in self.cve_cache:
                context_lines.append(f"{cve_id}: {self.cve_cache[cve_id]}")
            else:
                info = self._fetch_cve_info(cve_id)
                self.cve_cache[cve_id] = info
                context_lines.append(f"{cve_id}: {info}")

        return "\n".join(context_lines) if len(context_lines) > 1 else ""

    def _fetch_cve_info(self, cve_id: str) -> str:
        """Placeholder CVE lookup"""
        return f"Security vulnerability {cve_id} - consult NVD/MITRE for details."


class EnhancedSecurityPipeline:
    """Core security pipeline orchestrator"""

    def __init__(self, output_base: str = "outputs"):
        self.output_dir = Path(output_base)
        self.scans_dir = self.output_dir / "scans"
        self.image_remediation_dir = self.output_dir / "image_remediation"
        self.pod_remediation_dir = self.output_dir / "pod_remediation"
        self.safer_manifests_dir = self.output_dir / "safer_manifests"
        self.vector_db_dir = self.output_dir / "vector_db"

        for directory in [
            self.output_dir,
            self.scans_dir,
            self.image_remediation_dir,
            self.pod_remediation_dir,
            self.safer_manifests_dir,
            self.vector_db_dir
        ]:
            directory.mkdir(parents=True, exist_ok=True)

        self.knowledge_base = SecurityKnowledgeBase()
        self.collection = None
        self.chroma_client = None

        logging.info(f"Security pipeline initialized. Output: {self.output_dir}")

    def setup_rag_system(self):
        """Initialize RAG system with ChromaDB"""
        try:
            logging.info("Setting up RAG system with ChromaDB...")
            self.chroma_client = chromadb.PersistentClient(path=str(self.vector_db_dir))
            
            try:
                self.collection = self.chroma_client.get_collection(
                    name="security_scans",
                    embedding_function=embedding_functions.DefaultEmbeddingFunction()
                )
                logging.info("Loaded existing security_scans collection")
            except Exception:
                self.collection = self.chroma_client.create_collection(
                    name="security_scans",
                    embedding_function=embedding_functions.DefaultEmbeddingFunction(),
                    metadata={"description": "Security scan results"}
                )
                logging.info("Created new security_scans collection")
            
            logging.info("RAG system ready")
        except Exception as e:
            logging.error(f"Failed to setup RAG system: {e}")
            logging.warning("Continuing without RAG capabilities")

    def enhanced_index_scan_data(self, scan_type: str, scan_data: Dict[str, str]):
        """Index scan data into vector database for RAG (for image security module)"""
        if not self.collection:
            logging.warning("RAG system not initialized. Skipping indexing.")
            return

        try:
            documents = []
            metadatas = []
            ids = []
            doc_id = 0
            
            for scan_name, file_path in scan_data.items():
                if not file_path or not os.path.exists(file_path):
                    logging.warning(f"File does not exist for indexing: {file_path}")
                    continue
                    
                try:
                    content = self.safe_read_file(file_path)
                    if not content:
                        logging.warning(f"Empty file: {file_path}")
                        continue
                    
                    file_size = len(content)
                    logging.info(f"Indexing {scan_name} from {file_path} ({file_size:,} chars)")
                    
                    chunks = self._chunk_text(content, chunk_size=1000, overlap=100)
                    logging.info(f"Created {len(chunks)} chunks from {scan_name}")
                    
                    for i, chunk in enumerate(chunks):
                        documents.append(chunk)
                        metadatas.append({
                            "scan_type": scan_type,
                            "scan_name": scan_name,
                            "file_path": str(file_path),
                            "chunk_id": i,
                            "total_chunks": len(chunks)
                        })
                        ids.append(f"{scan_type}_{scan_name}_{doc_id}_{i}")
                    doc_id += 1
                    logging.info(f"✅ Successfully prepared {len(chunks)} chunks from {scan_name}")
                except Exception as e:
                    logging.error(f"❌ Could not index {file_path}: {e}", exc_info=True)

            if documents:
                try:
                    self.collection.add(documents=documents, metadatas=metadatas, ids=ids)
                    logging.info(f"✅ Successfully indexed {len(documents)} document chunks for {scan_type}")
                except Exception as e:
                    logging.error(f"❌ Failed to add documents to ChromaDB: {e}", exc_info=True)
            else:
                logging.warning(f"⚠️ No documents to index for {scan_type}")
        except Exception as e:
            logging.error(f"❌ Failed to index scan data: {e}", exc_info=True)

    def _chunk_text(self, text: str, chunk_size: int = 1000, overlap: int = 100) -> List[str]:
        """Split text into overlapping chunks"""
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

    def run_cmd(self, cmd: List[str], timeout: int = 60, capture_output: bool = True) -> Tuple[int, str, str]:
        """Execute shell command safely"""
        try:
            if capture_output:
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True, 
                    timeout=timeout,
                    encoding='utf-8',
                    errors='replace'
                )
            else:
                result = subprocess.run(cmd, timeout=timeout)
                return result.returncode, "", ""
            
            return result.returncode, result.stdout or "", result.stderr or ""
        except subprocess.TimeoutExpired:
            logging.error(f"Command timed out: {' '.join(cmd)}")
            return -1, "", "Command timed out"
        except Exception as e:
            logging.error(f"Command failed: {e}")
            return -1, "", str(e)

    def safe_read_file(self, file_path: str, encoding: str = 'utf-8') -> str:
        """Safely read file contents"""
        try:
            with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                return f.read()
        except Exception as e:
            logging.error(f"Failed to read {file_path}: {e}")
            return ""

    def pretty_print_list(self, items: List[Dict[str, str]], title: str = "Items"):
        """Pretty print a list of dictionaries"""
        if not items:
            print(f"\nNo {title.lower()} found.")
            return
        print(f"\n{'='*70}")
        print(f"{title.upper()} ({len(items)} found)")
        print(f"{'='*70}")
        for i, item in enumerate(items, start=1):
            print(f"\n{i}. ", end="")
            for key, value in item.items():
                print(f"{key}: {value}  ", end="")
        print(f"\n{'='*70}\n")

    def load_external_prompt(self, prompt_type: str) -> str:
        """Load external prompt template from disk"""
        prompt_files = {
            "image": "prompt.txt",
            "pod": "prompt_pod_security.txt",
            "dependency": "dependency_conflict_resolver.txt",
            "chat": "prompt_chatbot.txt"
        }
        
        prompt_file = prompt_files.get(prompt_type)
        if not prompt_file:
            logging.warning(f"Unknown prompt type: {prompt_type}")
            return ""
        
        prompt_path = Path(prompt_file)
        
        if not prompt_path.exists():
            logging.warning(f"Prompt file not found: {prompt_path.absolute()}")
            return ""
        
        try:
            content = self.safe_read_file(str(prompt_path))
            if content:
                logging.info(f"✅ Loaded external prompt from: {prompt_file} ({len(content)} chars)")
                return content
            else:
                logging.warning(f"Prompt file is empty: {prompt_file}")
                return ""
        except Exception as e:
            logging.error(f"Failed to load prompt {prompt_file}: {e}")
            return ""


def check_dependencies() -> bool:
    """Check if required tools are installed"""
    tools = {
        "docker": "Docker",
        "trivy": "Trivy",
        "kubectl": "Kubernetes CLI",
        "kube-score": "Kube-score",
        "kubescape": "Kubescape",
        "kyverno": "Kyverno"
    }
    missing = []
    for cmd, name in tools.items():
        try:
            subprocess.run(
                [cmd, "--version"], 
                capture_output=True, 
                timeout=5,
                encoding='utf-8',
                errors='replace'
            )
        except Exception:
            try:
                subprocess.run(
                    [cmd, "version"], 
                    capture_output=True, 
                    timeout=5,
                    encoding='utf-8',
                    errors='replace'
                )
            except Exception:
                missing.append(name)
    
    if missing:
        logging.warning(f"Missing tools: {', '.join(missing)}")
    
    return len(missing) == 0


def validate_environment() -> bool:
    """Validate runtime environment"""
    logging.info("Validating environment...")
    
    if sys.version_info < (3, 8):
        logging.error("Python 3.8+ required")
        return False

    api_key_file = Path("API_KEY.txt")
    if api_key_file.exists():
        logging.info("API_KEY.txt file found")
    elif not (os.getenv("OPENAI_API_KEY") or os.getenv("LLAMA_API_KEY")):
        logging.warning("No API key found. LLM features will be limited.")

    check_dependencies()
    logging.info("Environment validation complete")
    return True


if __name__ == "__main__":
    print("Testing common.py components...")
    validate_environment()
    pipeline = EnhancedSecurityPipeline()
    print(f"✓ Pipeline initialized: {pipeline.output_dir}")
    
    # Test LLM client with GPT-OSS-120B
    print("\n" + "="*70)
    print("Testing LLM Client (GPT-OSS-120B)")
    print("="*70)
    client = LlamaAPIClient(model="gpt-oss-120b")
    print(f"✓ LLM client initialized")
    print(f"  Provider: {client.provider}")
    print(f"  Model: {client.model}")
    print(f"  Base URL: {client.base_url}")
    
    print("\nAll components loaded successfully!")