"""
The proxyRequest and proxyResponse functions will be called for all requests  and responses made via ZAP, 
excluding some of the automated tools
If they return 'false' then the corresponding request / response will be dropped. 
You can use msg.setForceIntercept(true) in either method to force a break point

Note that new proxy scripts will initially be disabled
Right click the script in the Scripts tree and select "enable"  
"""

def proxyRequest(msg):
  # Debugging can be done using print like this
  print('proxyRequest called for url=' + msg.getRequestHeader().getURI().toString()); 
  return True;

def proxyResponse(msg):
  # Debugging can be done using print like this
  print('proxyResponse called for url=' + msg.getRequestHeader().getURI().toString()); 
  return True;

