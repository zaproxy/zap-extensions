"""
Passive scan rules should not make any requests.

Note that new passive scripts will initially be disabled
Right click the script in the Scripts tree and select "enable"
"""  

from org.zaproxy.zap.extension.pscan import PluginPassiveScanner;


def appliesToHistoryType(historyType):
    """Tells whether or not the scanner applies to the given history type.

    Args:
        historyType (int): The type (ID) of the message to be scanned.

    Returns:
        True to scan the message, False otherwise.

    """
    return PluginPassiveScanner.getDefaultHistoryTypes().contains(historyType);


def scan(ps, msg, src):
  """Passively scans the message sent/received through ZAP.

  Args:
    ps (ScriptsPassiveScanner): The helper class to raise alerts and add tags to the message.
    msg (HttpMessage): The HTTP message being scanned.
    src (Source): The HTML source of the message (if any). 

  """
  # Test the request and/or response here
  if (True):
    # Change to a test which detects the vulnerability
    # raiseAlert(risk, int confidence, String name, String description, String uri, 
    # String param, String attack, String otherInfo, String solution, String evidence, 
    # int cweId, int wascId, HttpMessage msg)
    # risk: 0: info, 1: low, 2: medium, 3: high
    # confidence: 0: false positive, 1: low, 2: medium, 3: high
    ps.raiseAlert(1, 1, 'Passive Vulnerability title', 'Full description', 
      msg.getRequestHeader().getURI().toString(), 
      'The param', 'Your attack', 'Any other info', 'The solution', '', 0, 0, msg);
