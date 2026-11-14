"""Provider-agnostic LLM access.

Business code depends on :class:`~backend.module2_chain.llm.base.LLMProvider`
only.  Swapping DeepSeek for a fine-tuned security model is a configuration
change (``.env`` / ``config.yaml``), never a code change.
"""

from backend.module2_chain.llm.base import (
    BaseLLMProvider,
    LLMError,
    LLMInvalidJSONError,
    LLMProvider,
    LLMProviderError,
    LLMSchemaError,
    LLMTimeoutError,
)
from backend.module2_chain.llm.factory import create_llm_provider
from backend.module2_chain.llm.schemas import (
    AttackAnalysisRequest,
    LLMAttackAnalysis,
    LLMCallRecord,
    LLMStage,
    LLMThreatEntity,
)

__all__ = [
    "AttackAnalysisRequest",
    "BaseLLMProvider",
    "LLMAttackAnalysis",
    "LLMCallRecord",
    "LLMError",
    "LLMInvalidJSONError",
    "LLMProvider",
    "LLMProviderError",
    "LLMSchemaError",
    "LLMStage",
    "LLMThreatEntity",
    "LLMTimeoutError",
    "create_llm_provider",
]
