# Product Security Using Generative AI

This project demonstrates an end-to-end security automation pipeline for **Docker images** and **Kubernetes manifests**, powered by **Generative AI** and **RAG (Retrieval-Augmented Generation)** into a single unified pipeline. It automatically scans Docker images, analyzes Kubernetes manifests, generates SBOMs, detects vulnerabilities, and stores all security data in a vector database. Using Retrieval-Augmented Generation, the system provides context-aware remediation by feeding real scan outputs into a lightweight LLM that produces secure Dockerfiles, fixed manifests, and detailed remediation reports.

The pipeline goes beyond static scanning by enabling iterative self-healing: each fix is regenerated, rebuilt, and rescanned until high and critical issues are resolved. The built-in Security Chatbot allows users to interact with the entire system, ask questions about vulnerabilities, understand failures, and receive accurate, data-driven explanations. Designed for real-world DevSecOps workflows, this solution automates product hardening, reduces manual analysis time, and ensures consistent, reliable security improvements across containers and **Kubernetes deployments.**. It was presented at **Nokia University Day 2025** and **won the best industry implemented Award**.

The system scans container images, analyzes Kubernetes manifests, stores findings in a vector database, and uses a lightweight LLM to automatically generate fixes, secure configurations, and reports.

---

## Overview

The pipeline includes:

- Scanning Docker images using **Trivy** and generating **SBOMs (CycloneDX)**  
- Storing SBOMs + scan outputs in **ChromaDB**  
- Using **GPT-OSS-120M** (via Groq API) to generate remediation and secure Dockerfiles  
- Analyzing Kubernetes manifests using **KubeScore**, **Kubescape**, and **Kyverno**  
- Generating production-ready, secure Kubernetes YAML files  
- Providing an interactive **Security Chatbot** powered by RAG  

---

## Architecture

Docker Image / K8s Manifest
|
Trivy / KubeScore / Kubescape / Kyverno
|
SBOM + Scan Outputs
|
ChromaDB (Vector Store)
|
LLM (GPT-OSS-120M) with RAG Context
|
Secure Dockerfile / Fixed YAML / Remediation Report
|
Chatbot


---

## Key Components

### Image Security
* ImageSecurityAnalyzer handles the full image scanning and remediation pipeline.
* Lists available Docker images and validates if the target image exists.
* Runs Trivy scans in three formats: text, JSON, and CycloneDX SBOM.
* Stores all scan outputs in the security pipeline’s /outputs/scans directory.
* Parses Trivy JSON and text to extract CVE ID, package name, installed/fixed versions, and severity.
* Classifies vulnerabilities by severity (HIGH, CRITICAL, etc.).
* Enriches vulnerabilities with real version data by querying PyPI, npm, Maven, Go, Ruby, etc.
* Verifies that suggested fix versions actually exist — avoiding false or broken recommendations.
* Detects image type and tech stack (Python, Node, Java, Go, etc.) and base OS (Debian, Alpine, etc.).
* Collects related files like Dockerfile, requirements.txt, or package.json to give the AI full context.
* Uses ChromaDB (RAG system) to fetch relevant prior scan data and CVE context for the same image or packages.
* Combines all information with a structured LLM prompt (prompt.txt) that defines remediation rules.
* The LlamaAPIClient (LLM) then generates a complete remediated Dockerfile (Dockerfile.secured).
* The AI ensures fixes for only HIGH/CRITICAL vulnerabilities, while ignoring low/medium.
* The generated Dockerfile enforces non-root users, version pinning, and secure package installs.
* The pipeline extracts the Dockerfile from the LLM output and saves it under /outputs/image_remediation.
* A validation step builds the new Dockerfile, runs Trivy again, and compares vulnerabilities with the original.
* If dependency or build errors occur, the system auto-fixes version conflicts and retries.
* If improvement is detected, the system keeps the new image and updates a markdown remediation report summarizing improvements.
* The report includes vulnerability counts, version changes, CVE summaries, and final verification results — providing a complete before-and-after comparison of image security.

  

### Pod Security
* PodSecurityAnalyzer module handles all pod-related scanning and remediation.
* It can work on local YAML files or live cluster resources extracted via kubectl get.
* Each manifest is first validated to ensure it’s syntactically correct.
* Three scanners run on every manifest:
* kube-score → general security best practices
* kubescape → NIST framework compliance
* kyverno → Kubernetes policy validation
* The pipeline counts CRITICAL, WARNING, and failed findings from all three tools.
* Outputs from each scanner are saved in outputs/scans/kubernetes_scans/.
* The scan data is parsed and combined into a single dataset per manifest.
* This scan data is indexed into ChromaDB, the vector database used for semantic search.
* Text embeddings are generated using the DefaultEmbeddingFunction for retrieval.
* This forms the RAG system, enabling the LLM to use real scan data as context.
* A specialized prompt (prompt_pod_security.txt) defines how the LLM should fix issues.
* The prompt instructs it to enforce non-root users, seccomp, read-only filesystems, resource limits, and network policies.
* The LlamaAPIClient queries an external or local LLM (like GPT/Llama) using the prompt + scan context.
* The LLM produces a complete, deployable, secure YAML manifest.
* If critical vulnerabilities existed, the improved manifest is saved in outputs/safer_manifests/.
* The improved YAML is rescanned with the same 3 tools to verify reduced issues.
* A diff is generated between old and new manifests showing applied changes.
* A comprehensive markdown report summarizing findings, fixes, and improvements is generated.
* The entire workflow is orchestrated by EnhancedSecurityPipeline for logging and directory management.
* Final results include total issues, improved manifests, and a remediation report summarizing before/after security posture.

### RAG Engine
* The RAG system stores all SBOMs, scan outputs, and remediation metadata into ChromaDB for semantic retrieval.
* Each SBOM generated by Trivy (CycloneDX) is parsed into structured components and indexed.
* Vulnerability reports, Dockerfile issues, Kubernetes scan outputs, and dependency metadata are also embedded.
* ChromaDB uses text embeddings generated through the DefaultEmbeddingFunction to support similarity search.
* Every scan run creates a unique dataset containing vulnerabilities, affected packages, versions, and descriptions.
* This dataset is flattened into text chunks and inserted into vector storage with associated metadata and IDs.
* During query time, the user’s question is embedded and matched against nearest vectors using top-k similarity search.
* The RAG subsystem automatically detects whether the query relates to Docker, SBOM, dependencies, Kubernetes, or general security.
* Retrieved context is concatenated into the LLM prompt to ensure the model answers based on real project data.
* This prevents hallucinations and allows precise, evidence-backed remediation suggestions.
* The system ensures that only relevant CVEs, packages, and findings from the user’s environment are used in the prompt.
* All retrieval operations are abstracted inside EnhancedSecurityPipeline for consistency.
* The RAG output directly influences the LLM-generated Dockerfile fixes, K8s manifest corrections, and vulnerability explanations.
* Each improved artifact (Dockerfile/YAML) is generated using strictly the context retrieved from ChromaDB, not assumptions.
* The RAG engine enables iterative scanning → vector indexing → LLM remediation cycles, forming a continuous security feedback loop.

### Security Chatbot
* The SecurityChatbot module serves as an intelligent interface for interactive debugging and security guidance.
* It classifies each message into categories such as security query, factual question, greeting, or exit intent.
* Offensive or irrelevant messages are filtered using a pattern-based intent filter with logging for blocked inpus.
* For security queries, the chatbot retrieves context from ChromaDB using the RAG engine.
* The chatbot can explain vulnerabilities, dependency conflicts, K8s policy violations, and remediation logic.
* It uses the LlamaAPIClient to query the LLM with a combined prompt containing both the user question and retrieved context.
* The chatbot ensures every response is grounded in real scan data rather than generic model knowledge.
* It automatically detects queries related to CVEs, Docker images, Kubernetes manifests, DevSecOps, and container hardening.
* The chatbot integrates directly with the EnhancedSecurityPipeline, allowing it to read stored outputs and previous scans.
* It supports contextual follow-up questions by referencing the latest SBOM or scan results in memory.
* Exit-intent detection ensures the chatbot can gracefully terminate interactions.
* The module logs inappropriate inputs, enabling safe filtering and preventing model misuse.
* Casual queries are handled with lightweight responses without invoking the LLM to save compute cost.
* Each chatbot response is formatted as a clear, technical explanation suitable for developers and security analysts.
* The chatbot acts as the interactive layer of the entire pipeline, bridging static scan outputs with LLM-powered remediation.
---

## Installation

##### System Dependencies
```bash
sudo apt update
sudo apt install -y docker.io kubectl python3 python3-pip curl jq wget
```

##### Trivy Installation
```bash
wget https://github.com/aquasecurity/trivy/releases/latest/download/trivy_Linux-64bit.tar.gz
tar -xvf trivy_Linux-64bit.tar.gz
sudo mv trivy /usr/local/bin/
```
##### KubeScore Installation
```bash
wget https://github.com/zegl/kube-score/releases/latest/download/kube-score_ubuntu_amd64
chmod +x kube-score_ubuntu_amd64
sudo mv kube-score_ubuntu_amd64 /usr/local/bin/kube-score
```
##### Kubescape Installation
```bash
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
```
##### Kyverno CLI Installation
```bash
curl -LO https://github.com/kyverno/kyverno/releases/latest/download/kyverno-cli_linux_x86_64.tar.gz
tar -xvf kyverno-cli_linux_x86_64.tar.gz
sudo mv kyverno /usr/local/bin/
```
##### Python Dependencies
```bash
pip install -r requirements.txt
```

