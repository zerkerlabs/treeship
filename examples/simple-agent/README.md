# Simple Agent Example

A minimal example showing how to add Treeship attestations to a Python agent.

## Setup

```bash
# Install dependencies
pip install treeship-sdk openai

# Set environment variables
export TREESHIP_API_KEY="your_treeship_key"
export TREESHIP_AGENT="simple-agent"
export OPENAI_API_KEY="your_openai_key"
```

## Run

```bash
python agent.py
```

## What It Does

1. Takes a user query
2. Calls OpenAI to generate a response
3. Attests the action with Treeship
4. Returns the response with a verification URL

## Files

- `agent.py` — The complete agent implementation
- `requirements.txt` — Dependencies
