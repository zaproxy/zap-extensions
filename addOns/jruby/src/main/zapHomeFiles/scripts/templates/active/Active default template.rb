# The scan function will typically be called for every parameter in every URL and Form for every page 
#
# Note that new active scripts will initially be disabled
# Right click the script in the Scripts tree and select "enable"  
      
require 'java'
java_package 'org.zaproxy.zap.extension.ascan'
java_import 'org.zaproxy.zap.extension.ascan.ActiveScript'
java_import 'org.zaproxy.zap.extension.ascan.ScriptsActiveScanner'
java_import 'org.parosproxy.paros.network.HttpMessage'
java_import 'org.parosproxy.paros.view.View'

class JRubyActiveScript 
  include Java::org.zaproxy.zap.extension.ascan.ActiveScript

  java_signature 'scan(ScriptsActiveScanner, HttpMessage, String, String)'
  def scan(sas, msg, param, value)
    # Debugging can be done to the Output tab like this
    # (not sure why print/puts doesnt work yet :(
    View.getSingleton().getOutputPanel().append(
      'scan called for url=' + msg.getRequestHeader().getURI().toString() + 
      ' param=' + param + ' value=' + value);

    # Copy requests before reusing them
    msg = msg.cloneRequest();

    # setParam (message, parameterName, newValue)
    sas.setParam(msg, param, 'Your attack');

    # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
    sas.sendAndReceive(msg, false, false);

    # Test the response here, and make other requests as required
    if (true)
  	  # Change to a test which detects the vulnerability
      # raiseAlert(risk, int confidence, String name, String description, String uri, 
      #		String param, String attack, String otherInfo, String solution, String evidence, 
      #		int cweId, int wascId, HttpMessage msg)
      # risk: 0: info, 1: low, 2: medium, 3: high
      # confidence: 0: false positive, 1: low, 2: medium, 3: high
      sas.raiseAlert(1, 1, 'Active Vulnerability title', 'Full description', 
      msg.getRequestHeader().getURI().toString(), 
        param, 'Your attack', 'Any other info', 'The solution ', '', 0, 0, msg);
    end
  end
end

# This is required - dont delete it or you'll break the script
JRubyActiveScript.new