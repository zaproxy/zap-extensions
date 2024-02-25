"""
The scanNode function will typically be called once for every page 
The scan function will typically be called for every parameter in every URL and Form for every page 

Note that new active scripts will initially be disabled
Right-click the script in the Scripts tree and select "enable"
"""

from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata

def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 12345
name: Active Vulnerability Title
description: Full description
solution: The solution
references:
  - Reference 1
  - Reference 2
category: INJECTION  # info_gather, browser, server, misc, injection
risk: INFO  # info, low, medium, high
confidence: LOW  # false_positive, low, medium, high, user_confirmed
cweId: 0
wascId: 0
alertTags:
  name1: value1
  name2: value2
otherInfo: Any other Info
status: alpha
""")

def scanNode(sas, msg):
  # Debugging can be done using print like this
  print('scan called for url=' + msg.getRequestHeader().getURI().toString())

  # Copy requests before reusing them
  msg = msg.cloneRequest()

  # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
  sas.sendAndReceive(msg, False, False)

  # Test the responses and raise alerts as below


def scan(helper, msg, param, value):
  # Debugging can be done using print like this
  print('scan called for url=' + msg.getRequestHeader().getURI().toString() + 
    ' param=' + param + ' value=' + value)

  # Copy requests before reusing them
  msg = msg.cloneRequest()

  # setParam (message, parameterName, newValue)
  helper.setParam(msg, param, 'Your attack')

  # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
  helper.sendAndReceive(msg, False, False)

  # Test the response here, and make other requests as required
  if True:
    # Change to a test which detects the vulnerability
    helper.newAlert().setParam(param).setAttack('Your attack').setEvidence('Evidence').setMessage(msg).raise()
