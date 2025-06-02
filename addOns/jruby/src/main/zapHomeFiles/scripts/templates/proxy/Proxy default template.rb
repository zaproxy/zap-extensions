# The proxyRequest and proxyResponse functions will be called for all requests and responses made via ZAP, 
# excluding some of the automated tools
# If they return 'false' then the corresponding request / response will be dropped. 
# You can use msg.setForceIntercept(true) in either method to force a break point
#
# Note that new proxy scripts will initially be disabled
# Right click the script in the Scripts tree and select "enable"  
#
require 'java'
java_import 'org.parosproxy.paros.network.HttpMessage'
java_import 'org.parosproxy.paros.view.View'

class JRubyProxyScript 
  include Java::org.zaproxy.zap.extension.script.ProxyScript

  java_signature 'proxyRequest(HttpMessage)'
  def proxyRequest(msg)
    # Debugging can be done to the Output tab like this
    # (not sure why print/puts doesnt work yet :(
    # puts('proxyRequest called for url=' + msg.getRequestHeader().getURI().toString() + "\n"); 
    View.getSingleton().getOutputPanel().append(
      'proxyRequest called for url=' + msg.getRequestHeader().getURI().toString() + "\n"); 

    return true
  end

  java_signature 'proxyResponse(HttpMessage)'
  def proxyResponse(msg)
    # Debugging can be done using print like this
    puts('proxyResponse called for url=' + msg.getRequestHeader().getURI().toString() + "\n"); 
    return true
  end
end

# This is required - dont delete it or you'll break the script
JRubyProxyScript.new
