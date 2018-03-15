/*
 * This script is intended to handle Magento authentication via ZAP.
 *
 * Magento login form uses the anti-CSRF token called "form_key".
 * The form key is generated once and used for the HTTP session.
 * In order to log in we need to load the login page first to parse the form key
 * and then send the form data along with the parsed form key.
 *
 * This script is based on the CasAuthentication script, so thank you guys for the example.
 *
 * @author Max Gopey <gopeyx@gmail.com>
 */

// Imports
var HttpRequestHeader = Java.type("org.parosproxy.paros.network.HttpRequestHeader");
var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
var URI = Java.type("org.apache.commons.httpclient.URI");
var Pattern = Java.type("java.util.regex.Pattern");

var debugMode = false;

function getRequiredParamsNames(){
    return ["loginUrl"];
}

function getOptionalParamsNames(){
    return ["extraPostData"];
}

function getCredentialsParamsNames(){
    return ["username", "password"];
}

function authenticate(helper, paramsValues, credentials) {
    debugMode && print("---- Magento authentication script has started ----");
    
    var loginUri = new URI(paramsValues.get("loginUrl"), false);
    
    // Perform a GET request to the login page to get the form_key
    var get = helper.prepareMessage();
    get.setRequestHeader(new HttpRequestHeader(HttpRequestHeader.GET, loginUri, HttpHeader.HTTP10));
    helper.sendAndReceive(get);
    var formParameters = parseFormParameters(get.getResponseBody().toString());
    
    // Build the request body using the credentials values and the form_key
    var requestBody = "login[username]=" + encodeURIComponent(credentials.getParam("username"));
    requestBody += "&login[password]=" + encodeURIComponent(credentials.getParam("password"));
    requestBody += "&form_key=" + encodeURIComponent(formParameters["form_key"]);

    // Add any extra post data provided
    var extraPostData = paramsValues.get("extraPostData");
    if (extraPostData !== null && !extraPostData.trim().isEmpty()) {
        requestBody += "&" + extraPostData.trim();
    }
    
    // Perform a POST request to authenticate
    debugMode && print("POST request body built for the authentication:\n  " + requestBody.replaceAll("&", "\n  "));
    var post = helper.prepareMessage();
    post.setRequestHeader(new HttpRequestHeader(HttpRequestHeader.POST, loginUri, HttpHeader.HTTP10));
    post.setRequestBody(requestBody);
    post.getRequestHeader().setContentLength(post.getRequestBody().length());
    helper.sendAndReceive(post);

    debugMode && print("---- Magento authentication script has finished ----\n");
    return post;
}

function parseFormParameters(response){
    var result = {};
    
    var regex = "<input.*name=\"(form_key)\".*value=\"([^\"]*)\"";
    var matcher = Pattern.compile(regex).matcher(response);
    while (matcher.find()) {
        result[matcher.group(1)] = matcher.group(2);
    }
    
    return result;
}