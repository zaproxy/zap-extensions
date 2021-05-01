"""
This authentication script can be used to authenticate in a web application via forms.
The submit target for the form, the name of the username field, the name of the password field and, optionally, any extra POST Data fields need to be specified after loading the script.

The username and the password need to be configured when creating any Users.
"""
import java.lang.String, jarray
import org.parosproxy.paros.network.HttpRequestHeader as HttpRequestHeader
import org.parosproxy.paros.network.HttpHeader as HttpHeader
from org.apache.commons.httpclient import URI
from urllib import quote

def authenticate(helper, paramsValues, credentials):
	"""The authenticate function will be called for authentications made via ZAP.

	The authenticate function is called whenever ZAP requires to authenticate, for a Context for which this script was selected as the Authentication Method. The function should send any messages that are required to do the authentication and should return a message with an authenticated response so the calling method.
	NOTE: Any message sent in the function should be obtained using the 'helper.prepareMessage()' method.

	Parameters:
		helper - a helper class providing useful methods: prepareMessage(), sendAndReceive(msg)
		paramsValues - the values of the parameters configured in the Session Properties -> Authentication panel. The paramsValues is a map, having as keys the parameters names (as returned by the getRequiredParamsNames() and getOptionalParamsNames() functions below)
		credentials - an object containing the credentials values, as configured in the Session Properties -> Users panel. The credential values can be obtained via calls to the getParam(paramName) method. The param names are the ones returned by the getCredentialsParamsNames() below
	"""
	print "Form-based authenticating via Jython script..."

	# Prepare the login request details
	requestUri = URI(paramsValues["Target URL"], False);
	requestMethod = HttpRequestHeader.POST;
	
	# Build the request body using the credentials values
	extraPostData = paramsValues["Extra POST data"];
	requestBody = paramsValues["Username field"] + "=" + quote(credentials.getParam("Username"), '');
	requestBody = requestBody + "&" + paramsValues["Password field"] + "=" + quote(credentials.getParam("Password"), '');
	if len(extraPostData.strip()) > 0:
		requestBody = requestBody + "&" + extraPostData.strip();

	# Build the actual message to be sent
	msg = helper.prepareMessage();
	msg.setRequestHeader(HttpRequestHeader(requestMethod, requestUri, HttpHeader.HTTP10));
	msg.setRequestBody(requestBody);

	# Send the authentication message and return it
	print "Sending %s request to %s with body: %s" % (requestMethod, requestUri, requestBody);
	helper.sendAndReceive(msg);
	print "Received response status code for authentication request: %d" % msg.getResponseHeader().getStatusCode();
	
	return msg;


def getRequiredParamsNames():
	"""Obtain the name of the mandatory/required parameters needed by the script.

	This function is called during the script loading to obtain a list of the names of the required configuration parameters, that will be shown in the Session Properties -> Authentication panel for configuration. They can be used to input dynamic data into the script, from the user interface (e.g. a login URL, name of POST parameters etc.)
	"""
	return jarray.array(["Target URL","Username field","Password field"], java.lang.String);


def getOptionalParamsNames():
	"""Obtain the name of the optional parameters needed by the script.

	This function is called during the script loading to obtain a list of the names of the optional configuration parameters, that will be shown in the Session Properties -> Authentication panel for configuration. They can be used to input dynamic data into the script, from the user interface (e.g. a login URL, name of POST parameters etc.).
	"""
	return jarray.array(["Extra POST data"], java.lang.String);


def getCredentialsParamsNames():
	"""Obtain the name of the credential parameters needed by the script.

	This function is called during the script loading to obtain a list of the names of the parameters that are required, as credentials, for each User configured corresponding to an Authentication using this script.
	"""
	return jarray.array(["Username", "Password"], java.lang.String);
