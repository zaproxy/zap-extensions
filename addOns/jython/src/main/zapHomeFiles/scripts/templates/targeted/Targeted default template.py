"""
Targeted scripts can only be invoked by you, the user, eg via a right-click option on the Sites or History tabs
"""

def invokeWith(msg):
  # Debugging can be done using print like this
  print('invokeWith called for url=' + msg.getRequestHeader().getURI().toString()); 
