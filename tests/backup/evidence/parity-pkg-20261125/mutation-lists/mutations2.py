"""Second round of lane PKG (after 8536def): the five mutations the first sweep of 5a2fd25 did not catch, and one mutation for each
alternative of the apt message patterns that a test now tells one by one. Each must make the tests fail; the controls must not."""
M = 'scripts/manage.py'
B = 'scripts/bootstrap-ubuntu.sh'
MUTATIONS = [
    # the five survivors of the first sweep
    ('plan made again from the old state', M, "            desired, state = replan()\n", "            desired = replan()[0]\n"),
    ('notices of the install lost', M, "result[key] = [*values, *result.get(key, [])]", "result[key] = list(values)"),
    ('reasons: removal needed', M, "r'need to be removed'", "r'need to be removedX'"),
    ('reasons: unsigned source', M, "|is not signed|no longer signed|", "|no longer signed|"),
    ('reasons: absent packages decide first', M, "    if absent and not kinds:\n        return index_reason(update, absent)\n", "    if absent:\n        return index_reason(update, absent)\n"),
    # every alternative of the patterns, one by one
    ('reasons: lock text of apt', M, "r'Could not get lock|is another process using it'", "r'is another process using it'"),
    ('reasons: ENOSPC', M, "r'No space left on device|enough free space'", "r'enough free space'"),
    ('reasons: unmet dependencies on stderr', M, "r'nmet dependencies|held broken packages'", "r'held broken packages'"),
    ('reasons: held broken packages', M, "r'nmet dependencies|held broken packages'", "r'nmet dependencies'"),
    ('reasons: Breaks', M, "(?:Conflicts|Breaks)", "(?:Conflicts)"),
    ('reasons: temporary failure resolving', M, "Temporary failure resolving|Could not (?:resolve|connect)|", "Could not (?:resolve|connect)|"),
    ('reasons: wicked', M, "|Unable to connect|wicked happened resolving'", "|Unable to connect'"),
    ('reasons: cannot initiate the connection', M, "\n                          r'|Cannot initiate the connection|Network is unreachable|No route to host'", "\n                          r'|Network is unreachable|No route to host'"),
    ('reasons: network is unreachable', M, "|Cannot initiate the connection|Network is unreachable|No route to host'", "|Cannot initiate the connection|No route to host'"),
    ('reasons: no route to host', M, "|Cannot initiate the connection|Network is unreachable|No route to host'", "|Cannot initiate the connection|Network is unreachable'"),
    ('reasons: connection timed out', M, "[Cc]onnection (?:timed out|failed|refused|reset)", "[Cc]onnection (?:failed|refused|reset)"),
    ('reasons: connection failed', M, "[Cc]onnection (?:timed out|failed|refused|reset)", "[Cc]onnection (?:timed out|refused|reset)"),
    ('reasons: connection reset', M, "[Cc]onnection (?:timed out|failed|refused|reset)", "[Cc]onnection (?:timed out|failed|refused)"),
    ('reasons: GPG error', M, "r'signature|GPG error|is not signed|", "r'signature|is not signed|"),
    ('reasons: no longer signed', M, "|is not signed|no longer signed|is expired|", "|is not signed|is expired|"),
    ('reasons: 410 is not gone', M, "GONE_TEXT = re.compile(r'^4(?:04|10) ')", "GONE_TEXT = re.compile(r'^404 ')"),
    ('reasons: unexpected size', M, "SYNC_TEXT = re.compile(r'Hash Sum mismatch|File has unexpected size')", "SYNC_TEXT = re.compile(r'Hash Sum mismatch')"),
    ('reasons: no installation candidate', M, "|Package '(\\S+)' has no installation candidate\"", "\""),
    ('reasons: warnings of a source count', M, "        kind = apt_problem(line) if line.startswith(('E:', 'W:')) else 'other'\n", "        kind = apt_problem(line) if line.startswith('E:') else 'other'\n"),
    ('reasons: a component warning is a problem', M, "if (kind != 'other' or line.startswith('E:')) and any(", "if True and any("),
    ('reasons: an error of no kind is no problem', M, "if (kind != 'other' or line.startswith('E:')) and any(", "if kind != 'other' and any("),
]
CONTROLS = [
    ('control: a comment', M, "# Waits (up to 300 s) for an automatic update", "# Waits (up to 300 seconds) for an automatic update"),
    ('control: a docstring', M, '"""The installed version and whether the engine\'s host tools work; read-only (`install` adds missing ones)."""',
     '"""The installed version and whether the engine\'s host tools work; read-only."""'),
]
