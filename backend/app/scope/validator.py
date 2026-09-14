from typing import Dict, Any, Tuple
from app.scope.scope_manager import ScopeManager, ScopeDefinition

def validate_action_scope(scope_def: Dict[str, Any], target_destination: str) -> Tuple[bool, str]:
    """Pre-flight check before any security tool executes"""
    manager = ScopeManager(ScopeDefinition(scope_def))
    return manager.is_target_allowed(target_destination)
