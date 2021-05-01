"""A script that provides custom input vectors that can be used during active
scans.

The option Enable Script Input Vectors must be enabled before starting the
scans.
Note that new scripts will initially be disabled, right click the script in the
Scripts tree and select Enable Script.
"""
import urllib


def parseParameters(helper, msg):
    """Parses/extracts the parameters from the HTTP message (request), to be
    later tested by the scanners.

    Args:
        helper (VariantCustom): Helper class that provides functions to add new
            parameters and process its values.
        msg (HttpMessage): The HTTP message (request) that will be scanned.

    """
    # Extract the attributes of a custom header...
    header = msg.getRequestHeader().getHeader('My-Custom-Header')
    if not header:
        return

    attributes = header.strip().split(';')
    for attribute in attributes:
        attribute = attribute.strip()
        if not attribute:
            continue
        data = attribute.split('=')
        name = data[0]
        value = urllib.unquote(data[1])
        helper.addParamHeader(name, value)


def setParameter(helper, msg, param, value, escaped):
    """Sets the new value (attack) of a parameter, called by the scanners
    during the active scan.

    Args:
        helper (VariantCustom): Helper class that provides functions to get the
            parameters and process its values.
        msg (HttpMessage): The HTTP message where the value should be injected.
        param (String): The name of the parameter.
        value (String): The value to inject.
        escaped (bool): True if the value is already escaped, False otherwise.

    """
    # Rebuild the header with the attack...
    header = ''
    for parameter in helper.getParamList():
        header += parameter.getName() + '='
        if parameter.getName() == param:
            header += urllib.quote(value)
        else:
            header += parameter.getValue()
        header += '; '

    msg.getRequestHeader().setHeader('My-Custom-Header', header)
