import org.parosproxy.paros.network.HttpMessage
import org.parosproxy.paros.network.HttpSender
import org.zaproxy.zap.extension.script.HttpSenderScriptHelper

// The sendingRequest and responseReceived functions will be called for all requests/responses sent/received by ZAP,
// including automated tools (e.g. active scanner, fuzzer, ...)

// Note that new HttpSender scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"

// 'initiator' is the component that initiated the request.
// For the latest list of values see the "Request Initiator" entries in the constants documentation:
// https://www.zaproxy.org/docs/constants/
// 'helper' just has one method at the moment: helper.getHttpSender() which returns the HttpSender
// instance used to send the request.
//
// New requests can be made like this:
// msg2 = msg.cloneAll() // msg2 can then be safely changed as required without affecting msg
// helper.getHttpSender().sendAndReceive(msg2, false);
// print('msg2 response=' + msg2.getResponseHeader().getStatusCode())

void sendingRequest(HttpMessage msg, int initiator, HttpSenderScriptHelper helper){
    if(initiator == HttpSender.PROXY_INITIATOR){
        println('Proxy Request sent for url=' + msg.getRequestHeader().getURI().toString())
    }
}

void responseReceived(HttpMessage msg, int initiator, HttpSenderScriptHelper helper) {
    if(initiator == HttpSender.PROXY_INITIATOR) {
        println('Proxy Response received for url=' + msg.getRequestHeader().getURI().toString())
    }
}

