"""Fixed stage markers only; no private values, callbacks or exception text."""
from contextvars import ContextVar
STAGES = frozenset(('initial','frame','fresh_target','source_capture','source_validated',
    'target_capture','target_documents','source_completion','login_scan','joined_ready','cleanup'))
_STAGE = ContextVar('emqx_preflight_stage',default='initial')
def mark(stage):
    if stage not in STAGES: raise ValueError()
    _STAGE.set(stage)
def current():
    return _STAGE.get()
class PreflightStageRefused(ValueError):
    def __init__(self, stage):
        if stage not in STAGES: raise ValueError()
        self.stage=stage
        super().__init__('fixed-preflight-stage-refused')
