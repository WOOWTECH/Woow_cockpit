"""Fixed stage markers only; no private values, callbacks or exception text."""
from contextvars import ContextVar
STAGES = frozenset(('initial','frame','fresh_target','source_capture','source_validated',
    'target_capture','target_quiescence','target_vendor','target_native','target_documents','source_completion','login_scan','joined_ready','cleanup'))
STAGES = STAGES | frozenset('target_native_'+p for p in ('wire','config_terms','config_secret_wrappers','provider_terms','schema_terms','inventory','tables','roots','references','connectors','cluster','api_bootstrap','authentication','listeners','dashboard','provider','mqtt_projection','readers'))
NATIVE_STAGES = frozenset(('typed_setup','effective_config','provider_state','native_inventory',
    'native_tables','table_storage','table_fragments','table_type','table_lock','schema_metadata',
    'table_size','table_schema','table_fold','table_row_terms','schema_terms','ticker_state',
    'table_receipts','stable_config','stable_provider','serialize_config','serialize_provider','encode_reply'))
NATIVE_REASONS = frozenset(('undef','badmatch','bad_argument','function_clause','no_exists','bad_type',
    'not_active','node_not_running','no_transaction','system_limit','storage_null_copies',
    'storage_null_nonempty','storage_external','storage_unknown','storage_unsupported',
    'fragments_unsupported','table_type_unsupported','table_row_limit','table_count_mismatch',
    'table_receipt_changed','config_changed','provider_changed','ticker_not_suspended','ticker_changed',
    'schema_record_invalid','unsupported_pid','unsupported_reference','unsupported_port',
    'unsupported_function','unsupported_bitstring','unsupported_term','native_refused'))
STAGES = STAGES | frozenset('native_'+p+'_'+r for p in NATIVE_STAGES for r in NATIVE_REASONS)
def native_refusal_stage(raw):
    import re
    if type(raw) is not bytes: return None
    # Ignore any preceding diagnostic bytes; never copy or decode them.
    match=re.fullmatch(rb'WOOWTARGETFAIL:([a-z_]+):([a-z_]+):ENDok',raw.strip().split(b'\n')[-1])
    if match is None: return None
    phase,reason=(v.decode('ascii') for v in match.groups())
    if phase not in NATIVE_STAGES or reason not in NATIVE_REASONS: return None
    return 'native_'+phase+'_'+reason
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
