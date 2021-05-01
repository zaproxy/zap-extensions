"""
The scanNode function will typically be called once for every page 
The scan function will typically be called for every parameter in every URL and Form for every page 

Note that new active scripts will initially be disabled
Right click the script in the Scripts tree and select "enable"  
"""
def scanNode(sas, msg):
  # Debugging can be done using print like this
  print('scan called for url=' + msg.getRequestHeader().getURI().toString());

  # Copy requests before reusing them
  msg = msg.cloneRequest();

  # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
  sas.sendAndReceive(msg, False, False);

  # Test the responses and raise alerts as below


def scan(sas, msg, param, value):
  # Debugging can be done using print like this
  print('scan called for url=' + msg.getRequestHeader().getURI().toString() + 
    ' param=' + param + ' value=' + value);

  # Copy requests before reusing them
  msg = msg.cloneRequest();

  # setParam (message, parameterName, newValue)
  sas.setParam(msg, param, 'Your attack');

  # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
  sas.sendAndReceive(msg, False, False);

  # Test the response here, and make other requests as required
  if (True):
  	# Change to a test which detects the vulnerability
    # raiseAlert(risk, int confidence, String name, String description, String uri, 
    #		String param, String attack, String otherInfo, String solution, String evidence, 
    #		int cweId, int wascId, HttpMessage msg)
    # risk: 0: info, 1: low, 2: medium, 3: high
    # confidence: 0: false positive, 1: low, 2: medium, 3: high
    sas.raiseAlert(1, 1, 'Active Vulnerability title', 'Full description', 
    msg.getRequestHeader().getURI().toString(), 
      param, 'Your attack', 'Any other info', 'The solution ', '', 0, 0, msg);
