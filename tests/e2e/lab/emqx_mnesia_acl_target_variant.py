"""Separate private synthetic FILE -> imported Mnesia ACL test policy.

Not installed by any workflow. Pass base/acl unchanged to OwnerProvision.create;
use its issued file observer and keep the same bytes through restore/rollback.
The original file-only policy is deliberately untouched. No source secrets or
caller-provided authorization rules are accepted by this factory.
"""
from dataclasses import dataclass

_FILE_ONLY = (b'authorization={no_match=deny,deny_action=ignore,sources=[{type=file,enable=true,'
              b'path="/opt/emqx/etc/lab-acl.conf"}]}\n')
_FALLBACK = (b'authorization={no_match=deny,deny_action=ignore,sources=[{type=file,enable=true,'
             b'path="/opt/emqx/etc/lab-acl.conf"},{type=built_in_database,enable=true}]}\n')
_ACL = (b'{allow, {username, "lab"}, all, ["lab/#"]}.\n'
        b'{deny, {username, "b1-sensor"}, subscribe, ["b1/secret/#"]}.\n')


@dataclass(frozen=True, repr=False)
class MnesiaAclTargetVariant:
    base: bytes
    acl: bytes

    def __repr__(self):
        return '<private synthetic Mnesia ACL target variant>'

    def unchanged(self, *, base, acl):
        """Private flow assertion; no receipts or capability minted here."""
        return type(base) is bytes and type(acl) is bytes and base == self.base and acl == self.acl



def create_mnesia_acl_target_variant():
    from emqx_real_owner_workflow import _target_base
    base = _target_base()
    # Refuse upstream layout changes rather than accidentally retaining a grant.
    if type(base) is not bytes or base.count(_FILE_ONLY) != 1 or not base.endswith(_FILE_ONLY):
        raise ValueError('fixed target authorization layout changed')
    return MnesiaAclTargetVariant(base[:-len(_FILE_ONLY)] + _FALLBACK, _ACL)
