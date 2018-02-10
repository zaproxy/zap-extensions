# Auxiliary variables/constants for processing.

import zlib;

# Called for each payload that needs to be processed.
# The type of variable 'payload' is string.

def process(payload):
    # Do some processing to payload
    compressed_payload = zlib.compress(payload);
    return compressed_payload;

