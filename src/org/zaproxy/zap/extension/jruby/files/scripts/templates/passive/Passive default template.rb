# The scan function will be called for request/response made via ZAP, excluding some of the automated tools
# Passive scan rules should not make any requests 
# Note that new passive scripts will initially be disabled
# Right click the script in the Scripts tree and select "enable"

require 'java'
java_package 'org.zaproxy.zap.extension.pscan'
java_import 'org.zaproxy.zap.extension.pscan.PassiveScript'
java_import 'org.zaproxy.zap.extension.pscan.scanner.ScriptsPassiveScanner'
java_import 'org.parosproxy.paros.network.HttpMessage'
java_import 'net.htmlparser.jericho.Source'
java_import 'org.parosproxy.paros.view.View'

class JRubyPassiveScript 
  include Java::org.zaproxy.zap.extension.pscan.PassiveScript

  java_signature 'scan(ScriptsPassiveScanner, HttpMessage, Source)'
  def scan(ps, msg, src)
    # Test the request and/or response here
    # Debugging can be done to the Output tab like this
    # (not sure why print/puts doesnt work yet :(
    View.getSingleton().getOutputPanel().append(
      'scan called for url=' + msg.getRequestHeader().getURI().toString());
    if (true)
      # Change to a test which detects the vulnerability
      # raiseAlert(risk, int reliability, String name, String description, String uri, 
      # String param, String attack, String otherInfo, String solution, String evidence, 
      # int cweId, int wascId, HttpMessage msg)
      # risk: 0: info, 1: low, 2: medium, 3: high
      # reliability: 0: falsePositive, 1: suspicious, 2: warning
      ps.raiseAlert(1, 1, 'Passive Vulnerability title', 'Full description', 
        msg.getRequestHeader().getURI().toString(), 
        'The param', 'Your attack', 'Any other info', 'The solution', '', 0, 0, msg);
    end
  end
end

# This is required - dont delete it or you'll break the script
JRubyPassiveScript.new