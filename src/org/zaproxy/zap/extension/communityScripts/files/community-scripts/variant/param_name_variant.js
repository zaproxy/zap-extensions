// This script provides a mechanism whereby the active scanner can inject payloads appended to the name of a parameter.
// This might be handy, for example: If you wanted to test for NoSQL Injections such as username=exampleuser&password[$ne]
// This script is designed to work with standard URL Query Parameters (GET) 
// and application/x-www-form-urlencoded (POST) parameters.

// The parseParameter function will typically be called for every page and 
// the setParameter function is called by each active plugin to bundle specific attacks

// Note that new custom input vector scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"

// Declare classes used herein
var VariantURLQuery = Java.type("org.parosproxy.paros.core.scanner.VariantURLQuery");
var VariantFormQuery = Java.type("org.parosproxy.paros.core.scanner.VariantFormQuery");
var NameValuePair = Java.type("org.parosproxy.paros.core.scanner.NameValuePair");
var vURLQuery;
var vFormQuery;

function parseParameters(helper, msg) {
    /** 
     *  GET http://example.org/?foo=bar
     *  GET http://example.org/?foo=bar&joe=smith
     *  POST http://example.org/
     *  foo=bar
     */

    if ('GET'.equals(msg.getRequestHeader().getMethod())) {
        vURLQuery = new VariantURLQuery();
        vURLQuery.setMessage(msg);
        helper.getParamList().addAll(vURLQuery.getParamList());
    } else if ('POST'.equals(msg.getRequestHeader().getMethod())) {
        vFormQuery= new VariantFormQuery()
        vFormQuery.setMessage(msg);
        helper.getParamList().addAll(vFormQuery.getParamList());
    }
}

function setParameter(helper, msg, param, value, escaped) {
    
    var pos=-1;
    for each (p in helper.getParamList()) { 
    // Will fail to properly position if there are multiple occurrences of the same name
        if (p.getName() == param) {
            pos = p.getPosition();
        }
    }

    if (pos == -1) {
        pos = 0; // We might clobber something but assume the first param anyway
    }

    // In the future [likely ZAP 2.8.0] it will be possible to get the current param directly via helper.getCurrentParam()
    var nvp = new NameValuePair(NameValuePair.TYPE_QUERY_STRING, helper.getParamName(pos)+value, helper.getParamValue(pos), pos);

    if (vURLQuery) {
        if (escaped) {
            vURLQuery.setEscapedParameter(msg, nvp, nvp.getName(), nvp.getValue());
        } else {
            vURLQuery.setParameter(msg, nvp, nvp.getName(), nvp.getValue());
        }
    } else if (vFormQuery) {
        if (escaped) {
            vFormQuery.setEscapedParameter(msg, nvp, nvp.getName(), nvp.getValue());
        } else {
            vFormQuery.setParameter(msg, nvp, nvp.getName(), nvp.getValue());
        }
    }
}