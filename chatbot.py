"""
Security chatbot module
Smart adaptive assistant for cybersecurity and general queries
"""

import logging
import re
from datetime import datetime
from typing import Tuple
from common import EnhancedSecurityPipeline, LlamaAPIClient


class SecurityChatbot:
    """Advanced, context-aware security assistant chatbot"""

    def __init__(self, pipeline: EnhancedSecurityPipeline):
        self.pipeline = pipeline
        self.llm_client = LlamaAPIClient(verbose=False)

        # Setup logging for blocked/offensive inputs
        logging.basicConfig(
            filename="blocked_inputs.log",
            level=logging.INFO,
            format="%(asctime)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # Offensive or irrelevant patterns (word-boundary safe)
        self.offensive_patterns = [
            r"\bnigga\b", r"\bnigger\b", r"\bfuck\b", r"\bshit\b", r"\basshole\b",
            r"\bcunt\b", r"\bbitch\b", r"\bfag\b", r"\bslut\b", r"\bwhore\b",
            r"\bkill yourself\b", r"\bgo die\b", r"\bterrorist\b", r"\bmurder\b",
            r"\brape\b", r"\bsuicide\b", r"\bsex\b", r"\bpenis\b", r"\bvagina\b",
            r"\bdick\b", r"\bboob\b", r"\bbreast\b", r"\bfuck you\b"
        ]

    # ------------------------------------------------------------
    # CLASSIFICATION HELPERS
    # ------------------------------------------------------------

    def is_security_related_query(self, query: str) -> bool:
        """Determine if the query is security-related"""
        security_keywords = [
            'cve', 'vulnerability', 'security', 'exploit', 'patch', 'fix',
            'critical', 'severity', 'remediation', 'docker', 'container',
            'kubernetes', 'k8s', 'scan', 'trivy', 'kubescore', 'kubescape',
            'owasp', 'nist', 'compliance', 'audit', 'penetration', 'threat',
            'risk', 'attack', 'breach', 'devsecops', 'cyber', 'malware',
            'virus', 'ransomware', 'firewall', 'encryption'
        ]
        query_lower = query.lower()
        return any(k in query_lower for k in security_keywords) or bool(re.search(r'CVE-\d{4}-\d+', query.upper()))

    def is_casual_query(self, query: str) -> bool:
        """Identify greetings, small talk, or self-identity queries"""
        casual_patterns = [
            r'^(hi|hello|hey|yo)$',
            r'^good\s+(morning|afternoon|evening|night)$',
            r'^(how\s+are\s+you|what\'s\s+up|help|who\s+are\s+you|what\s+are\s+you|thank(s| you)?)$'
        ]
        query_lower = query.lower().strip()
        return any(re.match(p, query_lower) for p in casual_patterns)


    def is_exit_intent(self, query: str) -> bool:
        """Detect if user intends to end the conversation"""
        exit_phrases = [
            'quit', 'exit', 'q', 'bye', 'goodbye', 'see you', 'stop',
            'end chat', 'close', 'that’s all', 'thats all', 'no more',
            'thank you bye', 'done', 'enough', 'end', 'talk later',
            'that will be all', 'we’re done', 'we are done', 'okay bye',
            'ok bye', 'bye for now', 'see ya', 'cya', 'leave now',
            'that’s it', 'that is it', 'that’s enough'
        ]
        query = query.lower().strip()
        return query == '' or any(phrase in query for phrase in exit_phrases)

    def is_factual_query(self, query: str) -> bool:
        """Detect factual/non-security general knowledge questions"""
        factual_patterns = [
            r'^who\s+is', r'^what\s+is', r'^when\s+is', r'^where\s+is',
            r'^define\s+', r'^meaning\s+of', r'^tell\s+me\s+about',
            r'^describe\s+', r'^give\s+me\s+info', r'^what\s+does',
            r'^who\s+was', r'^why\s+is'
        ]
        query_lower = query.lower().strip()
        return any(re.match(p, query_lower) for p in factual_patterns)

    def is_offensive_or_irrelevant(self, query: str) -> bool:
        """Detect offensive or irrelevant inputs"""
        text = query.lower().strip()
        for pattern in self.offensive_patterns:
            if re.search(pattern, text):
                logging.info(f"Blocked offensive input: {query}")
                return True
        return False

    # ------------------------------------------------------------
    # CONTEXT RETRIEVAL
    # ------------------------------------------------------------

    def retrieve_context(self, query: str, n_results: int = 5) -> Tuple[str, bool]:
        """Retrieve relevant context from vector DB or knowledge base"""
        if not self.pipeline.collection:
            return "", self.is_security_related_query(query)

        is_security_query = self.is_security_related_query(query)

        try:
            contexts = []
            results = self.pipeline.collection.query(query_texts=[query], n_results=n_results)

            if results["documents"][0]:
                contexts.extend(results["documents"][0])

            if is_security_query:
                cve_match = re.search(r'CVE-\d{4}-\d+', query.upper())
                if cve_match:
                    cve_results = self.pipeline.collection.query(
                        query_texts=[cve_match.group(0)],
                        n_results=3
                    )
                    if cve_results["documents"][0]:
                        contexts.extend(cve_results["documents"][0])

            unique_contexts = list(dict.fromkeys(contexts))
            context_text = ""

            if unique_contexts:
                context_text = "RELEVANT SECURITY DATA:\n\n"
                for i, doc in enumerate(unique_contexts[:n_results]):
                    doc_preview = doc[:1000] + "..." if len(doc) > 1000 else doc
                    context_text += f"--- DOCUMENT {i+1} ---\n{doc_preview}\n\n"

                if is_security_query:
                    kb_context = self.pipeline.knowledge_base.get_cve_context(query)
                    if kb_context:
                        context_text += kb_context
                return context_text, True

            if is_security_query:
                kb_context = self.pipeline.knowledge_base.get_cve_context(query)
                if kb_context:
                    return kb_context, True
                else:
                    return "No specific vulnerability data found. Providing general guidance.", True
            else:
                return "", False

        except Exception as e:
            logging.warning(f"Error retrieving context: {e}")
            return "", is_security_query

    # ------------------------------------------------------------
    # MAIN PROCESSING LOGIC
    # ------------------------------------------------------------

    def process_query(self, question: str) -> str:
        """Process a user query and generate the most relevant response"""

        # Check for offensive or irrelevant input first
        if self.is_offensive_or_irrelevant(question):
            return "📝 This isn’t something I can respond to."

        # Handle casual chats
        if self.is_casual_query(question):
            prompt = f"You are a friendly AI assistant. Respond naturally and warmly to: {question}"
            return self.llm_client.query(prompt, is_security_query=False)

        # Handle factual or general questions NOT related to security
        if self.is_factual_query(question) and not self.is_security_related_query(question):
            prompt = f"""You are a concise, intelligent, and neutral assistant.
Answer this question directly and factually.
Do NOT add cybersecurity, DevSecOps, or technical advice unless explicitly mentioned.
Avoid disclaimers unless accuracy is uncertain.

Question: {question}"""
            return self.llm_client.query(prompt, is_security_query=False)

        # Handle security-related questions
        context, is_security_query = self.retrieve_context(question)

        if is_security_query:
            if context and "No specific" not in context:
                prompt = f"""You are a senior cybersecurity expert and DevSecOps engineer.

Use the following context (if relevant) to answer precisely.

Question: {question}

Instructions:
- Be specific and practical
- Reference CVEs if relevant
- Include remediation steps and best practices
- Keep your answer clear and concise"""
            else:
                prompt = f"""You are a senior cybersecurity expert.

Question: {question}

Provide accurate, actionable guidance on:
- Common vulnerabilities (CVEs)
- Secure configurations
- Containers, Kubernetes, DevSecOps
- Compliance (OWASP, NIST)
Keep it short and practical."""
        else:
            # General factual or non-technical question (politics, history, etc.)
            prompt = f"""You are a general-purpose assistant who gives accurate, well-structured, and relevant answers.

Question: {question}

Respond directly, clearly, and concisely.
Avoid adding cybersecurity or technical context unless it is clearly relevant."""
            context = ""

        return self.llm_client.query(prompt, context, is_security_query=is_security_query)

    # ------------------------------------------------------------
    # INTERACTIVE LOOP
    # ------------------------------------------------------------

    def run(self):
        """Launch the interactive chatbot"""
        print("\n" + "=" * 70)
        print("SMART SECURITY ASSISTANT")
        print("=" * 70)
        print("I can help with:")
        print("• Security vulnerabilities (CVE analysis, remediation)")
        print("• Container / Kubernetes / DevSecOps queries")
        print("• General technical or factual questions")
        print("• Casual conversation")
        print("\nType 'quit', 'exit', or natural phrases like 'bye', 'done', 'stop' to end.")
        print("-" * 70)

        conversation_history = []

        while True:
            try:
                question = input("\n🔒 Security Assistant> ").strip()
                if self.is_exit_intent(question):
                    print("Thank you for using the Smart Security Assistant. Stay secure!")
                    break

                print("\n🤔 Thinking...")
                response = self.process_query(question)
                conversation_history.append({"question": question, "response": response})
                print(f"\n📝 {response}")

            except KeyboardInterrupt:
                print("\n\nSession interrupted. Goodbye!")
                break
            except Exception as e:
                print(f"Error: {e}")
                logging.error(f"Chatbot error: {e}")
