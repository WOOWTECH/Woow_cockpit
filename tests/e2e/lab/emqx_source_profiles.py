"""Private fixed source policy; never archive-, argv- or environment-selected paths."""
from dataclasses import dataclass, replace
from pathlib import Path


@dataclass(frozen=True)
class SourceProfile:
    archive: Path
    sha256: str
    frame_mode: bytes
    arch: str
    fixture_profile: str | None
    cold_receipt: tuple[int, int] | None
    file_dependency_profile: str | None = None


_BASE = Path('/home/woowtechopenclaw/.woowbk-lab/ha-fixtures/20261119-b1')
ARM_SOURCE = SourceProfile(
    _BASE / 'arm/woow-b1-arm-emqx-stopped-enc/woow-b1-arm-emqx-stopped-enc.tar',
    'b6eb257cc5790bee30500f929d51ade66bfa8354dbe5bb61ba7c4bc08582f664',
    b'S', 'aarch64', None, (28, 57502))
X86_SOURCE = SourceProfile(
    _BASE / 'x86/woow-b1-x86-emqx-stopped-enc/woow-b1-x86-emqx-stopped-enc.tar',
    '0a53e93888209316040af505484bba3ee3891c2ad2df7ae689bc0d4fd02690f9',
    b'X', 'amd64', 'owner-x86-20261121', None)


VENDOR_ACL_PROFILE = 'owner-pinned-image-vendor-acl-v1'
ARM_VENDOR_ACL = replace(ARM_SOURCE, frame_mode=b'V', file_dependency_profile=VENDOR_ACL_PROFILE)
X86_VENDOR_ACL = replace(X86_SOURCE, frame_mode=b'W', file_dependency_profile=VENDOR_ACL_PROFILE)
CONTEXT_PROFILE = 'owner-pinned-image-vendor-acl-republish-context-v1'
ARM_CONTEXT = replace(ARM_SOURCE, frame_mode=b'Y', file_dependency_profile=CONTEXT_PROFILE)
X86_CONTEXT = replace(X86_SOURCE, frame_mode=b'Z', file_dependency_profile=CONTEXT_PROFILE)
SOURCE_MODES = ('--source', '--x86-source', '--source-vendor-acl', '--x86-source-vendor-acl', '--source-vendor-acl-republish', '--x86-source-vendor-acl-republish')


def source_profile(mode):
    if mode == '--source':
        return ARM_SOURCE
    if mode == '--x86-source':
        return X86_SOURCE
    if mode == '--source-vendor-acl':
        return ARM_VENDOR_ACL
    if mode == '--x86-source-vendor-acl':
        return X86_VENDOR_ACL
    if mode == '--source-vendor-acl-republish':
        return ARM_CONTEXT
    if mode == '--x86-source-vendor-acl-republish':
        return X86_CONTEXT
    raise ValueError('fixed-source-mode-required')
