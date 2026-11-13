"""SETTINGS synchronization for the pinned Hypercorn benchmark fixture.

Hypercorn 0.18 seeds hyper-h2's current stream limit before sending SETTINGS.
A cold client may legally send a burst before receiving that limit (RFC 9113,
sections 6.5.2 and 6.5.3). Advertise the configured limit immediately, but let
hyper-h2 enforce it only after the corresponding SETTINGS acknowledgement.
This adapter affects the test server only.
"""
from h2.connection import H2Connection
from h2.settings import SettingCodes, Settings
import hypercorn.protocol
from hypercorn.protocol.h2 import H2Protocol


class NegotiatedH2Connection(H2Connection):
    def initiate_connection(self):
        # Serialize the configured limit into the first SETTINGS frame.
        super().initiate_connection()
        advertised = dict(self.local_settings.items())
        limit = advertised[SettingCodes.MAX_CONCURRENT_STREAMS]
        advertised[SettingCodes.MAX_CONCURRENT_STREAMS] = (1 << 32) - 1
        self.local_settings = Settings(client=False, initial_values=advertised)
        # The Settings setter queues a value; acknowledge() makes it current.
        self.local_settings.max_concurrent_streams = limit


class NegotiatedH2Protocol(H2Protocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        original = self.connection
        self.connection = NegotiatedH2Connection(config=original.config)
        self.connection.local_settings = original.local_settings
        self.connection.DEFAULT_MAX_INBOUND_FRAME_SIZE = original.DEFAULT_MAX_INBOUND_FRAME_SIZE


def install_settings_synchronization():
    # Hypercorn has no protocol factory hook. All Hypercorn listeners in this
    # benchmark process are our fixtures; installing once also permits parallel
    # fixtures without nested, process-global patch/restore contexts.
    hypercorn.protocol.H2Protocol = NegotiatedH2Protocol
