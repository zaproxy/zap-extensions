# 
# This script can be used by the Script Based Authentication Method to perform authentication for a given context.
#
# To use this script, select it in the Session Properties dialog -> Authentication panel.
#
require 'java'
java_package 'org.zaproxy.zap.authentication'
import org.parosproxy.paros.network.HttpRequestHeader
import org.parosproxy.paros.network.HttpHeader
import org.apache.commons.httpclient.URI

# The authenticate function will be called for authentications made via ZAP.
# 	
# The authenticate function is called whenever ZAP requires to authenticate, for a Context for which this script was selected as the Authentication Method. The function should send any messages that are required to do the authentication and should return a message with an authenticated response so the calling method.
# NOTE: Any message sent in the function should be obtained using the 'helper.prepareMessage()' method.
# 
# Params:
# helper : a helper class providing useful methods: prepareMessage(), sendAndReceive(msg)
# paramsValues : the values of the parameters configured in the Session Properties -> Authentication panel. The paramsValues is a map, having as keys the parameters names (as returned by the getRequiredParamsNames() and getOptionalParamsNames() functions below)
# credentials : an object containing the credentials values, as configured in the Session Properties -> Users panel. The credential values can be obtained via calls to the getParam(paramName) method. The param names are the ones returned by the getCredentialsParamsNames() below
java_signature 'authenticate(AuthenticationHelper, Map<String, String>, GenericAuthenticationCredentials)'
def authenticate(helper, paramsValues, credentials)

	puts("Authenticating via JRuby script...")
	# Prepare the login request details
	requestUri = URI.new(paramsValues["Target URL"], false);
	requestMethod = HttpRequestHeader::POST;
	
	# Build the request body using the credentials values
	extraPostData = paramsValues["Extra POST data"];
	requestBody = paramsValues["Username field"] + "=" + java.net.URLEncoder.encode(credentials.getParam("Username"), 'UTF-8');
	requestBody = requestBody + "&" + paramsValues["Password field"] + "=" + java.net.URLEncoder.encode(credentials.getParam("Password"), 'UTF-8');
	if extraPostData.strip.empty? == false
		requestBody = requestBody + "&" + extraPostData.strip;
	end
	
	# Build the actual message to be sent
	puts("Sending " + requestMethod + " request to " + paramsValues["Target URL"] + " with body: " + requestBody);
	msg=helper.prepareMessage();
	msg.setRequestHeader(HttpRequestHeader.new(requestMethod, requestUri, HttpHeader::HTTP10));
	msg.setRequestBody(requestBody);

	# Send the authentication message and return it
	helper.sendAndReceive(msg);
	puts("Received response status code for authentication request: " + msg.getResponseHeader().getStatusCode().to_s);
	return msg;
end

# Obtain the name of the mandatory/required parameters needed by the script.
# 
# This function is called during the script loading to obtain a list of the names of the required configuration parameters, that will be shown in the Session Properties -> Authentication panel for configuration. They can be used to input dynamic data into the script, from the user interface (e.g. a login URL, name of POST parameters etc.)
java_signature 'getRequiredParamsNames()'
def getRequiredParamsNames()
	return ["Target URL", "Username field", "Password field"]
end

# Obtain the name of the optional parameters needed by the script.
# 
# This function is called during the script loading to obtain a list of the names of the optional configuration parameters, that will be shown in the Session Properties -> Authentication panel for configuration. They can be used to input dynamic data into the script, from the user interface (e.g. a login URL, name of POST parameters etc.).
java_signature 'getOptionalParamsNames()'
def getOptionalParamsNames()
	return ["Extra POST data"]
end

# Obtain the name of the credential parameters needed by the script for each User.
# 
# This function is called during the script loading to obtain a list of the names of the parameters that are required, as credentials, for each User configured corresponding to an Authentication using this script.
java_signature 'getCredentialsParamsNames()'
def getCredentialsParamsNames()
	return ["Username", "Password"]
end
