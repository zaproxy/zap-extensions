"""
The process function will be called for every input (or input change)

Note that new encode-decode scripts will initially be disabled
Right click the script in the Scripts tree and select "enable"

For more details see 
	https://github.com/zaproxy/zap-extensions/tree/main/addOns/encoder/src/main/java/org/zaproxy/addon/encoder/processors/script/EncodeDecodeScriptHelper.java
"""

def process(helper, value):
    # Process the value however you like here, then return it as a EncodeDecodeResult
    # Easiest via helper.newResult
    return helper.newResult(value);
