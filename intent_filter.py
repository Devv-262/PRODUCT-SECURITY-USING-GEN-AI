"""
Intent Filter Module
--------------------
Filters user messages for inappropriate, irrelevant, or conversational intents.
Used by the SecurityChatbot to short-circuit responses when needed.
"""

import re


def handle_intent(message: str):
    """
    Analyze user input and decide if it should be handled directly.

    Returns:
        tuple[str, bool]:
            (response_message, handled)
            - response_message: the reply if handled internally
            - handled: True if the chatbot should NOT continue processing
    """

    if not message or not message.strip():
        return "Please say something.", True

    text = message.lower().strip()

    # ---------------------------------------
    # Offensive / disallowed terms
    # ---------------------------------------
    disallowed = [
        "nigga", "nigger", "fuck", "shit", "bitch", "slut", "rape",
        "terrorist", "murder", "kill yourself", "go die", "suicide",
        "cunt", "whore", "fag"
    ]

    for bad in disallowed:
        # Word-boundary match ensures we catch the exact word safely
        if re.search(rf"\b{re.escape(bad)}\b", text):
            return "📝 This isn’t something I can respond to.", True

    # ---------------------------------------
    # Exit or conversation-ending phrases
    # ---------------------------------------
    endings = [
        "bye", "goodbye", "see you", "talk later", "end chat",
        "that's all", "done", "enough", "thank you", "stop", "no more",
        "exit", "quit", "leave", "ok bye", "bye for now"
    ]
    if any(phrase in text for phrase in endings):
        return "👋 Goodbye! Ending the conversation.", True

    # ---------------------------------------
    # Friendly greetings / acknowledgments
    # ---------------------------------------
    greetings = [
        "hello", "hi", "hey", "good morning", "good afternoon",
        "good evening", "goodnight", "thanks", "thank you"
    ]
    for g in greetings:
        if re.search(rf"\b{g}\b", text):
            # Capitalize the original message for friendly echo
            return f"💬 {message.strip().capitalize()}!", True

    # ---------------------------------------
    # No match → let main chatbot process normally
    # ---------------------------------------
    return None, False
