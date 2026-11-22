"""Read-only native receipt component callable on an ALREADY OWNED candidate.

No CLI, container creation, restart, target selection, schema/table creation or
full native harness. Main may call this while holding the existing product owner
lease and candidate quiescence. Native behavior is exercised only when that owner
actually invokes it; host transport tests do not establish native acceptance.
"""
from woowbackup.ha_emqx import CONFIG_EXPR,MAX_HOCON,read_effective_config
from woowbackup.ha_emqx_acl_preservation import candidate_acl_receipt,refuse


def check_owned_candidate_acl_receipt(tmp):
    """Two complete native receipts around exact raw-config reads; no output.

    Fixed emqx-new role uses the same 10s/256B receipt command as product removal.
    Same candidate/node is mandatory: receipt includes node-specific persistent
    schema, not a source-versus-target comparator. Return None on success; never
    publish native counts/hashes. Caller owns tmp and excludes writers/issuance.
    """
    def config():
        return read_effective_config(lambda command:tmp.exec('emqx-new',command,
            timeout=10,max_output=MAX_HOCON,check=False))
    before=config()
    receipt=candidate_acl_receipt(tmp)
    if config()!=before or candidate_acl_receipt(tmp)!=receipt or config()!=before:
        refuse()
