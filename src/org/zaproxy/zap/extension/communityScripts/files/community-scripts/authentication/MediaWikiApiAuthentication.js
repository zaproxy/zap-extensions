/**
 * Script to authenticate on a MediaWiki site in ZAP via the API.
 *
 * MediaWiki protects against Login CSRF using a login token generated
 * on viewing the login page and storing it in the session and in a
 * hidden field in the login form. On submitting the login form, the
 * submitted token and the one in the session are compared to prevent
 * login CSRF. As a result, ZAP can't currently handle MediaWiki logins
 * with its form-based authentication. The MediaWiki API can also be used
 * to authenticate ZAP but it likewise protects against login CSRF by
 * returning a token on the first login request which must be submitted
 * on a second login request.
 *
 * The required parameter 'API URL' should be set to the path to
 * api.php, i.e. http://127.0.0.1/w/api.php
 *
 * The regex pattern to identify logged in responses could be set to:
 *     id="pt-logout"
 *
 * The regex pattern to identify logged out responses could be set to:
 *     id="pt-login"
 *
 * @author grunny
 */
 
// The following handles differences in printing between Java 7's Rhino JS engine
// and Java 8's Nashorn JS engine
if (typeof println == 'undefined') this.println = print;

function authenticate(helper, paramsValues, credentials) {
	println("Authenticating via JavaScript script...");
	importClass(org.parosproxy.paros.network.HttpRequestHeader);
	importClass(org.parosproxy.paros.network.HttpHeader);
	importClass(org.apache.commons.httpclient.URI);

	var authHelper = new MWApiAuthenticator(helper, paramsValues, credentials);

	return authHelper.login();
}

function getRequiredParamsNames(){
	return ['API URL'];
}

function getOptionalParamsNames(){
	return [];
}

function getCredentialsParamsNames(){
	return ['Username', 'Password'];
}

function MWApiAuthenticator(helper, paramsValues, credentials) {
	this.helper = helper;
	this.loginApiUrl = paramsValues.get('API URL') + '?action=login&format=json';
	this.userName = credentials.getParam('Username');
	this.password = credentials.getParam('Password');

	return this;
}

MWApiAuthenticator.prototype = {
	login: function () {
		var loginToken,
			requestBody = 'lgname=' + encodeURIComponent(this.userName) +
				'&lgpassword=' + encodeURIComponent(this.password),
			response = this.doRequest(
				this.loginApiUrl,
				HttpRequestHeader.POST,
				requestBody
			),
			parsedResponse = JSON.parse(response.getResponseBody().toString());

		if (parsedResponse.login.result == 'NeedToken') {
			loginToken = parsedResponse.login.token;
			requestBody += '&lgtoken=' + encodeURIComponent(loginToken);

			response = this.doRequest(
				this.loginApiUrl,
				HttpRequestHeader.POST,
				requestBody
			);
		}

		return response;
	},

	doRequest: function (url, requestMethod, requestBody) {
		var msg,
			requestUri = new URI(url, false);
			requestHeader = new HttpRequestHeader(requestMethod, requestUri, HttpHeader.HTTP10);

		msg = this.helper.prepareMessage();
		msg.setRequestHeader(requestHeader);
		msg.setRequestBody(requestBody);

		println('Sending ' + requestMethod + ' request to ' + requestUri + ' with body: ' + requestBody);
		this.helper.sendAndReceive(msg);
		println("Received response status code for authentication request: " + msg.getResponseHeader().getStatusCode());

		return msg;
	}
};
