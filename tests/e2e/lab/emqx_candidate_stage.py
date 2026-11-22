"""Fixed build diagnostics only; no product text, paths or source values."""
from contextvars import ContextVar
from woowbackup.ha_emqx import TABLES
STAGES=frozenset(('authorization','input_contract','image_version','archive_verify','source_reuse',
    'temp_objects','product_build','product_package','temp_cleanup','archive_final','private_cleanup'))
PRODUCT_STAGES=frozenset(('version','member_pass','node_name','source_broker','source_analysis','source_export','target_candidate','target_config','target_references','target_tls','target_snapshot','target_consistency','target_runtime','row_counts'))
ROW_COUNT_STAGES = {'product_row_counts_'+table+'_'+direction:(table,direction)
                    for table in TABLES for direction in ('underflow','overflow')}
PRODUCT_STAGES=PRODUCT_STAGES | frozenset(stage.removeprefix('product_') for stage in ROW_COUNT_STAGES)
STAGES=STAGES | frozenset('product_'+s for s in PRODUCT_STAGES)
KINDS=frozenset(('attribute','value','product','io','runtime','other'))
_STAGE=ContextVar('emqx_candidate_stage',default='authorization')
_ROW_COUNTS=ContextVar('emqx_candidate_row_counts',default=())
def mark(stage):
    if stage not in STAGES:raise ValueError()
    if stage in ('authorization','product_version','product_row_counts'):
        _ROW_COUNTS.set(())
    if stage in ROW_COUNT_STAGES:
        previous=_ROW_COUNTS.get()
        pair=ROW_COUNT_STAGES[stage]
        if pair not in previous:_ROW_COUNTS.set(previous+(pair,))
        if previous:return  # Failure phase identifies the first fixed mismatch.
    _STAGE.set(stage)
def row_count_diagnostics():
    return _ROW_COUNTS.get()
def current():return _STAGE.get()
def kind(error):
    from woowbackup.errors import BackupError
    if isinstance(error,AttributeError):return 'attribute'
    if isinstance(error,ValueError):return 'value'
    if isinstance(error,BackupError):return 'product'
    if isinstance(error,OSError):return 'io'
    if isinstance(error,RuntimeError):return 'runtime'
    return 'other'
