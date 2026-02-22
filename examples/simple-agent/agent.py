"""
Simple agent with Treeship attestation.

This example shows the minimal integration — just 3 lines of code:
1. Import the client
2. Create attestation after key actions
3. Include verification URL in response
"""
import os
from openai import OpenAI
from treeship import TreshipClient

# Initialize clients
openai_client = OpenAI()
treeship = TreshipClient()


def process_query(query: str) -> dict:
    """Process a user query and return attested response."""
    
    # 1. Call the LLM
    response = openai_client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": query}
        ]
    )
    
    answer = response.choices[0].message.content
    
    # 2. Attest the action (content is hashed, never sent)
    attestation = treeship.attest(
        action=f"Query processed: {query[:50]}...",
        inputs={
            "query": query,
            "model": "gpt-4",
            "response_preview": answer[:100]
        }
    )
    
    # 3. Return response with verification URL
    return {
        "answer": answer,
        "verification": attestation.url if attestation.attested else None
    }


if __name__ == "__main__":
    # Example usage
    result = process_query("What is the capital of France?")
    
    print(f"Answer: {result['answer']}")
    print(f"Verification: {result['verification']}")
