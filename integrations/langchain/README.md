# Treeship × LangChain Integration

Add verifiable audit trails to LangChain agents with a callback handler.

## Installation

```bash
pip install treeship-sdk langchain
```

## Quick Start

```python
from langchain.agents import AgentExecutor
from langchain.chat_models import ChatOpenAI
from treeship.integrations.langchain import TreshipCallbackHandler

# Create callback handler
treeship_callback = TreshipCallbackHandler(
    agent="my-langchain-agent",
    attest_on=["tool_start", "tool_end", "chain_end"]  # what to attest
)

# Add to your agent
agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    callbacks=[treeship_callback],
    verbose=True
)

# Run as normal — attestations happen automatically
result = agent_executor.run("Analyze this document and make a recommendation")
```

## Callback Handler

### TreshipCallbackHandler

```python
TreshipCallbackHandler(
    agent: str = None,           # Agent slug (default: from env)
    api_key: str = None,         # API key (default: from env)
    attest_on: list = None,      # Events to attest (default: all)
    include_outputs: bool = False # Include output hashes (default: False)
)
```

### Attestable Events

| Event | Description | Default |
|-------|-------------|---------|
| `chain_start` | Chain begins execution | ✓ |
| `chain_end` | Chain completes | ✓ |
| `tool_start` | Tool called | ✓ |
| `tool_end` | Tool returns | ✓ |
| `llm_start` | LLM called | ✗ |
| `llm_end` | LLM returns | ✗ |
| `agent_action` | Agent decides on action | ✓ |
| `agent_finish` | Agent completes | ✓ |

## Example with Tools

```python
from langchain.tools import Tool
from langchain.agents import initialize_agent, AgentType
from treeship.integrations.langchain import TreshipCallbackHandler

# Define tools
tools = [
    Tool(
        name="search",
        func=search_func,
        description="Search the web"
    ),
    Tool(
        name="calculator",
        func=calculator_func,
        description="Perform calculations"
    )
]

# Initialize with Treeship
treeship = TreshipCallbackHandler(agent="research-agent")

agent = initialize_agent(
    tools,
    llm,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
    callbacks=[treeship]
)

# Each tool call and decision is automatically attested
agent.run("What is the population of Tokyo divided by the area of Japan?")
```

## Manual Attestation

You can also attest manually within chains:

```python
from treeship import TreshipClient

client = TreshipClient(agent="my-agent")

# In your chain or tool
result = client.attest(
    action="Custom chain step completed",
    inputs={"step": "validation", "status": "passed"}
)
```

## Environment Variables

```bash
export TREESHIP_API_KEY="your_api_key"
export TREESHIP_AGENT="langchain-agent"
```

## Verification

All attestations are verifiable at `treeship.dev/verify/{id}`.
