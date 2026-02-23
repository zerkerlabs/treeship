"""
Treeship Skill for OpenClaw

Add verified attestations to your OpenClaw agents.

Installation:
    pip install treeship-sdk

Usage:
    from integrations.treeship_skill import TreeshipSkill
    
    agent = Agent(
        name="my-agent",
        skills=[TreeshipSkill()]
    )
"""

from treeship_sdk import Treeship

try:
    from openclaw import Skill
except ImportError:
    # Fallback for standalone use
    class Skill:
        name = ""
        description = ""


class TreeshipSkill(Skill):
    """
    Treeship verification skill for OpenClaw agents.
    
    Provides methods to create tamper-proof attestations of agent actions.
    """
    
    name = "treeship"
    description = "Create cryptographically verified records of agent actions"
    
    def __init__(self, api_key: str = None, default_agent: str = None):
        """
        Initialize the Treeship skill.
        
        Args:
            api_key: Treeship API key (or set TREESHIP_API_KEY env var)
            default_agent: Default agent name for attestations
        """
        self.ts = Treeship(api_key=api_key)
        self.default_agent = default_agent
    
    def attest(
        self, 
        action: str, 
        data: dict = None, 
        agent: str = None,
        metadata: dict = None
    ) -> str:
        """
        Create a verified attestation of an action.
        
        Args:
            action: Human-readable description of what happened
            data: Data to hash (never sent to Treeship, only the hash)
            agent: Agent name (uses default or context agent name if not provided)
            metadata: Optional metadata to include
        
        Returns:
            Verification URL
        
        Example:
            verify_url = self.attest(
                action="Approved loan for $50,000",
                data={"loan_id": "12345", "amount": 50000}
            )
        """
        agent_name = agent or self.default_agent or getattr(self, 'agent', {}).get('name', 'openclaw-agent')
        
        result = self.ts.attest(
            agent=agent_name,
            action=action,
            inputs_hash=self.ts.hash(data) if data else "no-input",
            metadata=metadata
        )
        
        return result.verify_url
    
    def verify(self, attestation_id: str) -> dict:
        """
        Verify an existing attestation.
        
        Args:
            attestation_id: The attestation ID to verify
        
        Returns:
            Verification result with signature validity
        """
        return self.ts.verify(attestation_id)
    
    def get_history_url(self, agent: str = None) -> str:
        """
        Get the verification page URL for an agent.
        
        Args:
            agent: Agent name (uses default if not provided)
        
        Returns:
            URL to the agent's verification page
        """
        agent_name = agent or self.default_agent or "openclaw-agent"
        return f"https://treeship.dev/verify/{agent_name}"


# Convenience function for standalone use
def create_skill(api_key: str = None, default_agent: str = None) -> TreeshipSkill:
    """Create a Treeship skill instance."""
    return TreeshipSkill(api_key=api_key, default_agent=default_agent)
