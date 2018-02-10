// Author : aine-rb from Sopra Steria (based on the script of thc202 from the OWASP ZAP development team)

// This script is heavily based on the "Simple Form-Based Authentication.js" template
// It can be used to authenticate in a webapplication via a form submission followed by a GET request
// The submit target for the form, the name of the username field, the name of the password field
// and the URL of the GET target need to be specified after loading the script.
// The username and the password need to be configured when creating any Users.

// The authenticate function is called whenever ZAP requires to authenticate, for a Context for which
// this script was selected as the Authentication Method. The function should send any messages that
// are required to do the authentication and should return a message with an authenticated response
// so the calling method.
//
// NOTE: Any message sent in the function should be obtained using the 'helper.prepareMessage()' method.


// Parameters:
//   helper - a helper class providing useful methods: prepareMessage(), sendAndReceive(msg)
//   paramsValues - the values of the parameters configured in the Session Properties - Authentication panel.
//                      The paramsValues is a map, having as keys the parameters names (as returned by the
//				    getRequiredParamsNames() and getOptionalParamsNames() functions below)
//   credentials - an object containing the credentials values, as configured in the Session Properties - Users panel.
//                      The credential values can be obtained via calls to the getParam(paramName) method. The param
//				    names are the ones returned by the getCredentialsParamsNames() below

// Make sure any Java classes used explicitly are imported
var HttpRequestHeader = Java.type('org.parosproxy.paros.network.HttpRequestHeader');
var HttpHeader = Java.type('org.parosproxy.paros.network.HttpHeader');
var URI = Java.type('org.apache.commons.httpclient.URI');
var AuthenticationHelper = Java.type('org.zaproxy.zap.authentication.AuthenticationHelper');
var Cookie = Java.type('org.apache.commons.httpclient.Cookie');

function authenticate(helper, paramsValues, credentials) {
    print("Authenticating via JavaScript script...");

    // Prepare the login submission request details
    var requestUri = new URI(paramsValues.get("Submission Form URL"), false);
    var requestMethod = HttpRequestHeader.POST;

    // Build the submission request body using the credential values
    var requestBody = paramsValues.get("Username field") + "=" + encodeURIComponent(credentials.getParam("Username"));
    requestBody += "&" + paramsValues.get("Password field") + "=" + encodeURIComponent(credentials.getParam("Password"));

    // Build the submission request header
    var requestHeader = new HttpRequestHeader(requestMethod, requestUri, HttpHeader.HTTP11);

    // Build the submission request message
    var msg = helper.prepareMessage();
    msg.setRequestHeader(requestHeader);
    msg.setRequestBody(requestBody);
    msg.getRequestHeader().setContentLength(msg.getRequestBody().length());

    // Send the submission request message
    print("Sending " + requestMethod + " request to " + requestUri + " with body: " + requestBody);
    helper.sendAndReceive(msg, false); // don't follow redirects in order to set correctly the cookie
    print("Received response status code: " + msg.getResponseHeader().getStatusCode());
    AuthenticationHelper.addAuthMessageToHistory(msg);

    // Retrieve session cookies in the Set-Cookie header, this can be used in case cookies are not set correctly
    /*var cookies = msg.getResponseHeader().getHttpCookies("");
    var state = helper.getCorrespondingHttpState();
    for (var iterator = cookies.iterator(); iterator.hasNext();) {
        var cookie = iterator.next();
        var cookieName = cookie.getName();
        var cookieValue = cookie.getValue();
        print("Manually adding cookie: " + cookieName + "=" + cookieValue);
        state.addCookie(new Cookie("", cookieName, cookieValue, "", 999999, false));
        requestHeader.setHeader(HttpHeader.COOKIE, "SESSIONID=" + cookieValue);
	}*/

    // Build the GET request details
    requestUri = new URI(paramsValues.get("Target URL"), false);
    requestMethod = HttpRequestHeader.GET;

    // Build the GET request header
    requestHeader = new HttpRequestHeader(requestMethod, requestUri, HttpHeader.HTTP11);

    // Build the GET request message
    msg = helper.prepareMessage();
    msg.setRequestHeader(requestHeader);
    msg.getRequestHeader().setContentLength(msg.getRequestBody().length());

    // Send the GET request message
    print("Sending " + requestMethod + " request to " + requestUri);
    helper.sendAndReceive(msg, true);
    print("Received response status code: " + msg.getResponseHeader().getStatusCode());

    return msg;
}

// This function is called during the script loading to obtain a list of the names of the required configuration parameters,
// that will be shown in the Session Properties -  Authentication panel for configuration. They can be used
// to input dynamic data into the script, from the user interface (e.g. a login URL, name of POST parameters etc.)
function getRequiredParamsNames(){
    return ["Submission Form URL", "Username field", "Password field", "Target URL"];
}

// This function is called during the script loading to obtain a list of the names of the optional configuration parameters,
// that will be shown in the Session Properties -  Authentication panel for configuration. They can be used
// to input dynamic data into the script, from the user interface (e.g. a login URL, name of POST parameters etc.)
function getOptionalParamsNames(){
    return [];
}

// This function is called during the script loading to obtain a list of the names of the parameters that are required,
// as credentials, for each User configured corresponding to an Authentication using this script
function getCredentialsParamsNames(){
    return ["Username", "Password"];
}
