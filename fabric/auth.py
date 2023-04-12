from functools import partial
from getpass import getpass

from paramiko import Agent
from paramiko.auth_strategy import (
    AuthStrategy,
    Password,
    InMemoryPrivateKey,
)


class OpenSSHAuthStrategy(AuthStrategy):
    """
    Auth strategy that tries very hard to act like the OpenSSH client.

    For example, it accepts a `~paramiko.config.SSHConfig` and uses any
    relevant ``IdentityFile`` directives from that object, along with keys from
    your home directory and any local SSH agent. Keys specified at runtime are
    tried last, just as with ``ssh -i /path/to/key`` (this is one departure
    from the legacy/off-spec auth behavior observed in older Paramiko and
    Fabric versions).

    We explicitly do not document the full details here, because the point is
    to match the documented/observed behavior of OpenSSH. Please see the `ssh
    <https://man.openbsd.org/ssh>`_ and `ssh_config
    <https://man.openbsd.org/ssh_config>`_ man pages for more information.
    """

    # Skimming openssh code gives us the following behavior to crib from:
    # - parse cli (initializing identity_files if any given)
    # - parse user config, then system config _unless_ user gave cli config
    # path; this will also add to identity_files if any IdentityFile found
    # (after the CLI ones)
    # - lots of value init, string interpolation, etc
    # - if no other identity_files exist at this point, fill in the defaults:
    #   - in order: rsa, dsa, ecdsa, ecdsa_sk, ed25519, xmss (???)
    # - initial connection (ssh_connect() - presumably handshake/hostkey/kex)
    # - load all identity_files (and any implicit certs of those)
    # - eventually runs pubkey_prepare() which, per its own comment,
    # loads/assembles key material in this order:
    #   - certs - config file, then cli, skipping any non-user (?) certs
    #   - agent keys that are also listed in the config file; then others
    #   - non-agent config file keys (this seems like it includes cli and
    #   implicit defaults)
    #   - once list is assembled, drop anything not listed in config pubkey
    #   algorithms list
    # - auth_none to get list of acceptable authmethods
    # - while-loops along that, or next returned, list of acceptable
    # authmethods, using a handler table, so eg a 'standard' openssh on both
    # ends might start with 'publickey,password,keyboard-interactive'; so it'll
    # try all pubkeys found above before eventually trying a password prompt,
    # and then if THAT fails, it will try kbdint call-and-response (similar to
    # password but where server sends you the prompt(s) it wants displayed)

    def __init__(self, ssh_config, username):
        """
        Extends superclass with additional inputs.

        Specifically:
        - ``username``, which is unified by our caller so we don't have to -
          it's a synthesis of CLI, runtime, invoke/fabric-configuration, and
          ssh_config configuration.

        Also handles connecting to an SSH agent, if possible, for easier
        lifecycle tracking.
        """
        super().__init__(ssh_config=ssh_config)
        self.username = username
        # NOTE: Agent seems designed to always 'work' even w/o a live agent, in
        # which case it just yields an empty key list.
        self.agent = Agent()

    def get_pubkeys(self):
        # TODO: config file based CERTS from ssh_config[identityfile] (for us,
        # I guess this means this is the time to do the 'do any of these have
        # certs next to them?' thing
        # TODO: invoke-config-based CERTS, ditto (this does technically
        # conflate cli and 'non-ssh_config config', but that is difficult to
        # tease apart now, and falls outside OpenSSH-mimicry anyways, so
        # punting)
        for agent_pkey in self.agent.get_keys():
            # TODO: we technically want to reorder these so ones that also
            # exist in ssh_config come first, per openssh
            # TODO: so hm, do we want to be carting username around everywhere,
            # or do we want some middleware that injects it?
            yield InMemoryPrivateKey(username=self.username, pkey=agent_pkey)
        # TODO: any other pubkeys (ie non cert, non agent) - so this would be
        # in the order of cli-given/inv-config-driven, then ssh_config, then
        # implicit (except really, the latter only come into play if those
        # prior two categories were empty!)

    def get_sources(self):
        # TODO: initial none-auth + tracking the response's allowed types.
        # however, SSHClient never did this deeply, and there's no guarantee a
        # server _will_ send anything but "any" anyways...
        # Public keys of all kinds typically first.
        yield from self.get_pubkeys()
        user = self.username
        host = self.transport.hostname
        prompter = partial(getpass, f"{user}@{host}'s password: ")
        # Then password.
        yield Password(username=self.username, password_getter=prompter)
        # TODO: password-interactive, both by its lonesome & as part of 2FA
        # TODO: how about manually passed-in pkeys (similar to connect's old
        # pkey kwarg)? that can surely wait, 99% of users will be using cli /
        # fab-config / ssh_config / agent...and it falls outside of
        # OpenSSH-mimicry.

    def authenticate(self, *args, **kwargs):
        # Just do what our parent would, except make sure we close() after.
        try:
            return super().authenticate(*args, **kwargs)
        finally:
            self.close()

    def close(self):
        """
        Shut down any resources we ourselves opened up.
        """
        # TODO: bare try/except here as "best effort"? ugh
        self.agent.close()

    def __del__(self):
        # Insurance for us never actually getting authenticate() called.
        self.close()
