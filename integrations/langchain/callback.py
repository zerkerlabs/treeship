"""
Treeship LangChain callback handler — automatic attestation for LangChain agents.

Usage:
    from treeship.integrations.langchain import TreshipCallbackHandler
    
    handler = TreshipCallbackHandler(agent="my-agent")
    agent = AgentExecutor(..., callbacks=[handler])
"""
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

try:
    from langchain.callbacks.base import BaseCallbackHandler
    from langchain.schema import AgentAction, AgentFinish, LLMResult
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    BaseCallbackHandler = object


class TreshipCallbackHandler(BaseCallbackHandler if LANGCHAIN_AVAILABLE else object):
    """
    LangChain callback handler that creates Treeship attestations.
    
    Args:
        agent: Agent slug for attestations
        api_key: Treeship API key (default: from env)
        attest_on: List of events to attest. Options:
                   chain_start, chain_end, tool_start, tool_end,
                   llm_start, llm_end, agent_action, agent_finish
        include_outputs: Whether to include output hashes (default: False)
    """
    
    def __init__(
        self,
        agent: Optional[str] = None,
        api_key: Optional[str] = None,
        attest_on: Optional[List[str]] = None,
        include_outputs: bool = False,
    ):
        if not LANGCHAIN_AVAILABLE:
            raise ImportError("langchain is required for this integration. Install with: pip install langchain")
        
        super().__init__()
        
        from treeship import TreshipClient
        
        self.client = TreshipClient(api_key=api_key, agent=agent)
        self.agent = agent or self.client.agent
        self.include_outputs = include_outputs
        
        # Default events to attest
        self.attest_on = set(attest_on or [
            "chain_start", "chain_end",
            "tool_start", "tool_end",
            "agent_action", "agent_finish"
        ])
    
    def _should_attest(self, event: str) -> bool:
        return event in self.attest_on
    
    def _attest(self, action: str, inputs: Optional[Dict] = None):
        """Create attestation. Never raises."""
        try:
            self.client.attest(action=action, inputs=inputs, agent=self.agent)
        except Exception:
            pass
    
    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> None:
        if self._should_attest("chain_start"):
            chain_name = serialized.get("name", "unknown")
            self._attest(
                action=f"[langchain] Chain started: {chain_name}",
                inputs={"chain": chain_name, "run_id": str(run_id)}
            )
    
    def on_chain_end(
        self,
        outputs: Dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        if self._should_attest("chain_end"):
            attest_inputs = {"run_id": str(run_id)}
            if self.include_outputs:
                attest_inputs["outputs"] = outputs
            self._attest(
                action=f"[langchain] Chain completed",
                inputs=attest_inputs
            )
    
    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> None:
        if self._should_attest("tool_start"):
            tool_name = serialized.get("name", "unknown")
            self._attest(
                action=f"[langchain] Tool called: {tool_name}",
                inputs={"tool": tool_name, "run_id": str(run_id)}
            )
    
    def on_tool_end(
        self,
        output: str,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        if self._should_attest("tool_end"):
            attest_inputs = {"run_id": str(run_id)}
            if self.include_outputs:
                attest_inputs["output"] = output
            self._attest(
                action=f"[langchain] Tool completed",
                inputs=attest_inputs
            )
    
    def on_agent_action(
        self,
        action: AgentAction,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        if self._should_attest("agent_action"):
            self._attest(
                action=f"[langchain] Agent action: {action.tool}",
                inputs={
                    "tool": action.tool,
                    "run_id": str(run_id),
                    "log": action.log[:200] if action.log else None
                }
            )
    
    def on_agent_finish(
        self,
        finish: AgentFinish,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        if self._should_attest("agent_finish"):
            attest_inputs = {"run_id": str(run_id)}
            if self.include_outputs and finish.return_values:
                attest_inputs["return_values"] = finish.return_values
            self._attest(
                action=f"[langchain] Agent finished",
                inputs=attest_inputs
            )
    
    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        if self._should_attest("llm_start"):
            model = serialized.get("name", serialized.get("model_name", "unknown"))
            self._attest(
                action=f"[langchain] LLM called: {model}",
                inputs={"model": model, "run_id": str(run_id)}
            )
    
    def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        if self._should_attest("llm_end"):
            self._attest(
                action=f"[langchain] LLM completed",
                inputs={"run_id": str(run_id)}
            )
    
    def on_chain_error(
        self,
        error: Union[Exception, KeyboardInterrupt],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        self._attest(
            action=f"[langchain] Chain error: {type(error).__name__}",
            inputs={"run_id": str(run_id), "error_type": type(error).__name__}
        )
    
    def on_tool_error(
        self,
        error: Union[Exception, KeyboardInterrupt],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        self._attest(
            action=f"[langchain] Tool error: {type(error).__name__}",
            inputs={"run_id": str(run_id), "error_type": type(error).__name__}
        )
