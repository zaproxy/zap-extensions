"""
The process function will be called for every input (or input change)

Note that new encode-decode scripts will initially be disabled
Right click the script in the Scripts tree and select "enable"  
"""
from org.zaproxy.addon.encoder.processors import EncodeDecodeResult

def process(value):
    # Process the value however you like here, then return it as a EncodeDecodeResult
    return EncodeDecodeResult(value);
