"""Fixed build diagnostics only; no product text, paths or source values."""
from contextvars import ContextVar
STAGES=frozenset(('authorization','input_contract','image_version','archive_verify','source_reuse',
    'temp_objects','product_build','product_package','temp_cleanup','archive_final','private_cleanup'))
PRODUCT_STAGES=frozenset(('version','member_pass','node_name','source_broker','source_analysis','source_export','target_candidate','target_config','target_references','target_tls','target_snapshot','target_consistency','target_runtime','row_counts'))
STAGES=STAGES | frozenset('product_'+s for s in PRODUCT_STAGES)
KINDS=frozenset(('attribute','value','product','io','runtime','other'))
_STAGE=ContextVar('emqx_candidate_stage',default='authorization')
def mark(stage):
    if stage not in STAGES:raise ValueError()
    _STAGE.set(stage)
def current():return _STAGE.get()
def kind(error):
    from woowbackup.errors import BackupError
    if isinstance(error,AttributeError):return 'attribute'
    if isinstance(error,ValueError):return 'value'
    if isinstance(error,BackupError):return 'product'
    if isinstance(error,OSError):return 'io'
    if isinstance(error,RuntimeError):return 'runtime'
    return 'other'
