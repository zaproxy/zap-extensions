import org.parosproxy.paros.network.HttpMessage

/*
The proxyRequest and proxyResponse functions will be called for all requests  and responses made via ZAP,
excluding some of the automated tools
If they return 'false' then the corresponding request / response will be dropped.
You can use msg.setForceIntercept(true) in either method to force a break point

Note that new proxy scripts will initially be disabled
Right click the script in the Scripts tree and select "enable"
*/

boolean proxyRequest(HttpMessage msg){
    println('proxyRequest called for url=' + msg.getRequestHeader().getURI().toString())
    return true
}

boolean proxyResponse(HttpMessage msg){
    println('proxyResponse called for url=' + msg.getRequestHeader().getURI().toString())
    return true
}
