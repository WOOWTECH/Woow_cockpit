"""Explicit private target-policy selector for the workflow owner's future hook.

No workflow entrypoint, CLI, source-mode/frame changes, monkeypatch or transport.
FILE baseline stays exact. Imported mode leaves all source roles to Mnesia.
"""
from emqx_mnesia_acl_target_variant import MnesiaAclTargetVariant, create_mnesia_acl_target_variant

FILE_BASELINE = 'file-baseline'
IMPORTED_MNESIA = 'imported-mnesia-acl'
_LAB_ONLY = b'{allow, {username, "lab"}, all, ["lab/#"]}.\n'


def target_policy_for_mode(mode):
    """Private bytes for OwnerProvision.create; source mode is a separate input.

    No default/alias, workflow replacement, evidence or permission claim is added.
    Owner must retain the issued observer and actual pre/post byte assertions.
    """
    if type(mode) is not str:
        raise ValueError('unsupported fixed target policy mode')
    if mode == FILE_BASELINE:
        from emqx_real_owner_workflow import _target_base, _target_acl
        return MnesiaAclTargetVariant(_target_base(), _target_acl())
    if mode == IMPORTED_MNESIA:
        variant = create_mnesia_acl_target_variant()
        return MnesiaAclTargetVariant(variant.base, _LAB_ONLY)
    raise ValueError('unsupported fixed target policy mode')
