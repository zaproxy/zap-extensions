# The sendingRequest and responseReceived functions will be called for all
# requests/responses sent/received by ZAP, including automated tools (e.g.
# active scanner, fuzzer, ...)

# Note that new HttpSender scripts will initially be disabled
# Right click the script in the Scripts tree and select "enable"

# 'initiator' is the component the initiated the request:
#      1   PROXY_INITIATOR
#      2   ACTIVE_SCANNER_INITIATOR
#      3   SPIDER_INITIATOR
#      4   FUZZER_INITIATOR
#      5   AUTHENTICATION_INITIATOR
#      6   MANUAL_REQUEST_INITIATOR
#      7   CHECK_FOR_UPDATES_INITIATOR
#      8   BEAN_SHELL_INITIATOR
#      9   ACCESS_CONTROL_SCANNER_INITIATOR
#     10   AJAX_SPIDER_INITIATOR
# For the latest list of values see the HttpSender class:
# https://github.com/zaproxy/zaproxy/blob/master/zap/src/main/java/org/parosproxy/paros/network/HttpSender.java
# 'helper' just has one method at the moment: helper.getHttpSender() which
# returns the HttpSender instance used to send the request.
#
# New requests can be made like this:
# msg2 = msg.cloneAll()
# helper.getHttpSender().sendAndReceive(msg2, false)
# puts('msg2 response code =' + msg2.getResponseHeader().getStatusCode().to_s)


def sendingRequest(msg, initiator, helper)
	# Debugging can be done using print like this
	puts('sendingRequest called for url=' +
		msg.getRequestHeader().getURI().toString())
end

def responseReceived(msg, initiator, helper)
	# Debugging can be done using print like this
	puts('responseReceived called for url=' +
		msg.getRequestHeader().getURI().toString())
end
