"""
Passive scan rules should not make any requests.

Note that new passive scripts will initially be disabled
Right-click the script in the Scripts tree and select "enable"
"""  

from org.zaproxy.zap.extension.pscan import PluginPassiveScanner
from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata

def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 12345
name: Passive Vulnerability Title
description: Full description
solution: The solution
references:
  - Reference 1
  - Reference 2
risk: INFO  # info, low, medium, high
confidence: LOW  # false_positive, low, medium, high, user_confirmed
cweId: 0
wascId: 0
alertTags:
  name1: value1
  name2: value2
otherInfo: Any other info
status: alpha
""")

def appliesToHistoryType(historyType):
    """Tells whether or not the scanner applies to the given history type.

    Args:
        historyType (int): The type (ID) of the message to be scanned.

    Returns:
        True to scan the message, False otherwise.

    """
    return PluginPassiveScanner.getDefaultHistoryTypes().contains(historyType)


def scan(helper, msg, src):
  """Passively scans the message sent/received through ZAP.

  Args:
    helper (PassiveScriptHelper): The helper class to raise alerts and add tags to the message.
    msg (HttpMessage): The HTTP message being scanned.
    src (Source): The HTML source of the message (if any). 

  """
  # Test the request and/or response here
  if True:
    # Change to a test which detects the vulnerability
    helper.newAlert().setParam('The param').setEvidence('Evidence').raise()
