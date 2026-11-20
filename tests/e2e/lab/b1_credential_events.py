"""Offline validation of Omnigent 0.21.0 runner credential events.

The caller supplies events from a trusted, complete producer and a registry callable.
This module does not observe a runner, read files, or start a process.  A snapshot
of auth_tokens.json alone is not a complete event stream.
"""


class CredentialCoverageError(ValueError):
    """Coverage is incomplete; messages deliberately contain no input data."""


def register_runner_events(events, register):
    """Validate a complete ordered stream, then register each distinct credential.

    Events are login, refresh, and end records, with contiguous sequence numbers
    starting at zero. A login must request and receive a refresh grant. Refresh
    responses contain access_token and may omit refresh_token, in which case the
    current grant remains valid (as in Omnigent cli_auth). 'end' is an explicit
    producer assertion that capture ended without a gap; it cannot by itself
    establish the trustworthiness of that producer.
    """
    if not isinstance(events, list) or len(events) < 2:
        raise CredentialCoverageError('incomplete event stream')
    values = []
    have_login = False
    ended = False
    for index, event in enumerate(events):
        if not isinstance(event, dict) or type(event.get('sequence')) is not int or event['sequence'] != index or ended:
            raise CredentialCoverageError('invalid event sequence')
        kind = event.get('kind')
        if kind == 'login' and not have_login and index == 0:
            if event.get('issue_refresh') is not True:
                raise CredentialCoverageError('refresh grant was not requested')
            fields = ('token', 'refresh_token')
            have_login = True
        elif kind == 'refresh' and have_login:
            fields = ('access_token',)
            if 'refresh_token' in event:
                fields += ('refresh_token',)
        elif kind == 'end' and have_login and index == len(events) - 1:
            ended = True
            continue
        else:
            raise CredentialCoverageError('unexpected event type')
        for field in fields:
            value = event.get(field)
            if not isinstance(value, str) or len(value) < 6:
                raise CredentialCoverageError('required credential missing or invalid')
            if value not in values:
                values.append(value)
    if not ended:
        raise CredentialCoverageError('event stream has no completion record')
    for index, value in enumerate(values):
        register(f'RUNNER_ISSUED_{index}', value)
    return len(values)
