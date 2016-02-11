// At the moment ZAP supports only FORM parameter tokens. This script is designed to look for a CSRF token value in the response body using a regex pattern match. Besides capturing the CSRF token value from response body, it also uses the latest value for all outgoing requests irrespective of where the CSRF token is located i.e. FORM parameters or URL parameters or Cookie parameters.
// This script is generic, however, it requires enough configuration setup for application under test.
// Following are several configuration entries that need to be modified in the script.
// antiCsrfTokenName - Anti CSRF Token name in the application under test.
// urlRegEx - Regex for the request URL that returns CSRF token value in its response body.
// csrfTokenValueRegEx - Regex for capturing the CSRF token value from the response body. Make sure to use grouping in the regex, to capture a certain portion of the match.
// matcherGroupNumber - Group number to be matched and captured as new Anti CSRF token value. This value will be replaced in all subsequent requests that has a CSRF token in the request.
// parameterTypesList - An array of one or more parameter types to be looked in, for replacing the anti CSRF token value in the outgoing requests. Supported values in the array: formParamType, urlParamType, cookieParamType.

// REPLACE the values for the variables as applicable to your application.

// Regular expression for the request URI that returns CSRF token in response.
// If the application under test returns csrf token in every response or in response to more than request, set a generic regex that matches with host name or domain name of the application.
// REPLACE the value with RegEx for your application.
var urlRegEx = /commonjs.action/i;

// Regular expression to find the anti csrf token value.
// Make sure that regex pattern has a group defined, and group number defined in matcherGroupNumber returns the required anti csrf token value.
// REPLACE the value with RegEx for your application.
var csrfTokenValueRegEx = /var secureToken\s*=\s*'([A-Za-z0-9_-]*)';/i;

// Group number to look for the csrf token value in the csrfTokenValueRegEx.
// REPLACE the value with the group number to match with csrf token value from csrfTokenValueRegEx.
var matcherGroupNumber = 1;

// Csrf token name. Name of the form parameter to be treated as AntiCsrfTokenName.
// REPLACE the value with csrf token name for your application.
var antiCsrfTokenName = "secureToken";

var formParamType = org.parosproxy.paros.network.HtmlParameter.Type.form;
var urlParamType = org.parosproxy.paros.network.HtmlParameter.Type.url;
var cookieParamType = org.parosproxy.paros.network.HtmlParameter.Type.cookie;

// HTML parameter types to look for antiCsrfTokenName and replace with new anti CSRF Token value.
// Comma separated list of HTML parameter types.
// Supported values: formParamType, urlParamType, cookieParamType.
// REPLACE the value with the params to scan for CSRF token and replace with latest vaule.
var parameterTypesList = [formParamType, urlParamType, cookieParamType];

//println ("AntiCsrfTokenValue: " + org.zaproxy.zap.extension.script.ScriptVars.getGlobalVar("anti.csrf.token.value"))

function sendingRequest(msg, initiator, helper) {
    // println('sendingRequest called for url=' + msg.getRequestHeader().getURI().toString())
    var numberOfParameterTypes = parameterTypesList.length;
    for (var index=0; index < numberOfParameterTypes; index++) {
        if (parameterTypesList[index] != null && parameterTypesList[index] === formParamType) {
            var formParams = msg.getFormParams();
            // println ("Form Params before update: " + formParams);
            var updatedFormParams = modifyParams(formParams);
            // println ("Form Params after update: " + updatedFormParams);
            msg.setFormParams(updatedFormParams);
        } else if (parameterTypesList[index] != null && parameterTypesList[index] === urlParamType) {
            var urlParams = msg.getUrlParams();
            // println ("Url Params before update: " + urlParams);
            var updatedUrlParams = modifyParams(urlParams);
            // println ("Url Params after update: " + updatedUrlParams);
            msg.setGetParams(updatedUrlParams);
        } else if (parameterTypesList[index] != null && parameterTypesList[index] === cookieParamType) {
            var cookieParams = msg.getCookieParams();
            // println ("Cookie Params before update: " + cookieParams);
            var updatedCookieParams = modifyParams(cookieParams);
            // println ("Cookie Params after update: " + updatedCookieParams);
            msg.setCookieParams(updatedCookieParams);
        }
    }
}

function responseReceived(msg, initiator, helper) {
    // println('responseReceived called for url=' + msg.getRequestHeader().getURI().toString())
    if (msg.getRequestHeader().getURI().toString().match(urlRegEx) != null) {
        var csrfTokenValue = msg.getResponseBody().toString().match(csrfTokenValueRegEx);
        if (csrfTokenValue != null && csrfTokenValue.length > matcherGroupNumber) {
            println('Latest CSRF Token value: ' + csrfTokenValue[matcherGroupNumber]);
            org.zaproxy.zap.extension.script.ScriptVars.setGlobalVar("anti.csrf.token.value", csrfTokenValue[matcherGroupNumber]);
        }
    }
}

function modifyParams(params) {
    var iterator = params.iterator();
    while(iterator.hasNext()) {
        var param = iterator.next();
        // Check if the url parameters has the antiCsrfTokenName in it.
        if (param.getName().equals(antiCsrfTokenName)) {
            var secureTokenValue = param.getValue();
            var antiCsrfTokenValue = org.zaproxy.zap.extension.script.ScriptVars.getGlobalVar("anti.csrf.token.value");
            // Check for the value of AntiCsrfTokenName in the existing request with the latest value captured from previous requests.
            if (antiCsrfTokenValue != null && !secureTokenValue.equals(antiCsrfTokenValue)) {
                param.setValue(antiCsrfTokenValue);
                break;
            }
        }
    }
    return params;
}
