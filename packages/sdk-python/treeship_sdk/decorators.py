"""
Treeship decorators — zero-code attestation for common patterns.

These decorators automatically create attestations for function calls
without requiring any manual attestation code.

Example:
    @attest_reasoning
    def make_decision(context):
        reasoning = "User meets criteria because..."
        return {"decision": "approved", "reasoning": reasoning}

    # The decorator automatically:
    # 1. Hashes the input (context)
    # 2. Calls the function
    # 3. Creates an attestation with action="make_decision executed"
    # 4. Returns the result unchanged
"""
import functools
import hashlib
import json
import os
import time
from typing import Any, Callable, Optional, TypeVar, ParamSpec

# Lazy import to avoid circular dependency
_client = None

P = ParamSpec("P")
R = TypeVar("R")


def _get_client():
    """Get or create the global Treeship client."""
    global _client
    if _client is None:
        from .client import Treeship
        _client = Treeship()
    return _client


def _hash_value(value: Any) -> str:
    """Hash any value to a consistent string."""
    try:
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        canonical = str(value)
    return hashlib.sha256(canonical.encode()).hexdigest()


def attest_memory(
    action: Optional[str] = None,
    agent: Optional[str] = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """
    Decorator to attest memory state changes.
    
    Use for functions that read or write persistent state (database, cache, files).
    
    Args:
        action: Custom action description (default: "{func_name} executed")
        agent: Agent slug (default: from env or client default)
    
    Example:
        @attest_memory
        def save_user_preferences(user_id: str, prefs: dict):
            db.save(user_id, prefs)
            return {"saved": True}
    """
    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            # Capture input state
            inputs_hash = _hash_value({"args": args, "kwargs": kwargs})
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Attest (non-blocking, never fails)
            try:
                client = _get_client()
                attestation_action = action or f"{func.__name__} executed"
                client.attest(
                    action=f"[memory] {attestation_action}",
                    inputs={"inputs_hash": inputs_hash, "result_hash": _hash_value(result)},
                    agent=agent,
                )
            except Exception:
                pass  # Never block on attestation failure
            
            return result
        return wrapper
    return decorator


def attest_reasoning(
    action: Optional[str] = None,
    agent: Optional[str] = None,
    extract_reasoning: Optional[Callable[[Any], str]] = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """
    Decorator to attest reasoning/decision-making.
    
    Use for functions that make decisions or contain reasoning logic.
    The decorator will attempt to extract reasoning from the result.
    
    Args:
        action: Custom action description
        agent: Agent slug
        extract_reasoning: Optional function to extract reasoning from result
                          (default: looks for 'reasoning' key in dict results)
    
    Example:
        @attest_reasoning
        def evaluate_application(app_data: dict) -> dict:
            # ... analysis logic ...
            return {
                "decision": "approved",
                "reasoning": "Applicant meets all criteria: income > $50k, credit > 700"
            }
    """
    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            # Capture input
            inputs_hash = _hash_value({"args": args, "kwargs": kwargs})
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Extract reasoning if possible
            reasoning_hash = None
            if extract_reasoning:
                try:
                    reasoning = extract_reasoning(result)
                    reasoning_hash = _hash_value(reasoning)
                except Exception:
                    pass
            elif isinstance(result, dict) and "reasoning" in result:
                reasoning_hash = _hash_value(result["reasoning"])
            
            # Attest
            try:
                client = _get_client()
                attestation_action = action or f"{func.__name__} decision"
                
                attest_inputs = {
                    "inputs_hash": inputs_hash,
                    "result_hash": _hash_value(result),
                }
                if reasoning_hash:
                    attest_inputs["reasoning_hash"] = reasoning_hash
                
                client.attest(
                    action=f"[reasoning] {attestation_action}",
                    inputs=attest_inputs,
                    agent=agent,
                )
            except Exception:
                pass
            
            return result
        return wrapper
    return decorator


def attest_performance(
    action: Optional[str] = None,
    agent: Optional[str] = None,
    threshold_ms: Optional[int] = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """
    Decorator to attest execution performance.
    
    Records execution time and optionally only attests if above threshold.
    
    Args:
        action: Custom action description
        agent: Agent slug
        threshold_ms: Only attest if execution time exceeds this (default: always attest)
    
    Example:
        @attest_performance(threshold_ms=1000)
        def process_large_document(doc: str) -> dict:
            # ... expensive processing ...
            return {"summary": "..."}
    """
    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            # Time execution
            start = time.perf_counter()
            result = func(*args, **kwargs)
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            
            # Skip if under threshold
            if threshold_ms is not None and elapsed_ms < threshold_ms:
                return result
            
            # Attest
            try:
                client = _get_client()
                attestation_action = action or f"{func.__name__} completed"
                
                client.attest(
                    action=f"[perf] {attestation_action}",
                    inputs={
                        "inputs_hash": _hash_value({"args": args, "kwargs": kwargs}),
                        "execution_ms": elapsed_ms,
                    },
                    agent=agent,
                )
            except Exception:
                pass
            
            return result
        return wrapper
    return decorator
