/**
 * Script to authenticate on a MediaWiki site in ZAP via the login form.
 *
 * MediaWiki protects against Login CSRF using a login token generated
 * on viewing the login page and storing it in the session and in a
 * hidden field in the login form. On submitting the login form, the
 * submitted token and the one in the session are compared to prevent
 * login CSRF. As a result, ZAP can't currently handle MediaWiki logins
 * with its form-based authentication. So, we need to first get the login
 * token, then use it to perform the login request.
 *
 * The required parameter 'Login URL' should be set to the path to
 * Special:UserLogin, i.e. http://127.0.0.1/wiki/Special:UserLogin
 *
 * The regex pattern to identify logged in responses could be set to:
 *     id="pt-logout"
 *
 * The regex pattern to identify logged out responses could be set to:
 *     id="pt-login"
 *
 * @author grunny
 */

var HttpRequestHeader = Java.type("org.parosproxy.paros.network.HttpRequestHeader");
var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
var URI = Java.type("org.apache.commons.httpclient.URI");
var Source = Java.type("net.htmlparser.jericho.Source");

function authenticate(helper, paramsValues, credentials) {
	print("Authenticating via JavaScript script...");

	var authHelper = new MWAuthenticator(helper, paramsValues, credentials),
		loginToken = authHelper.getLoginToken();

	return authHelper.doLogin(loginToken);
}

function getRequiredParamsNames(){
	return ['Login URL'];
}

function getOptionalParamsNames(){
	return [];
}

function getCredentialsParamsNames(){
	return ['Username', 'Password'];
}

function MWAuthenticator(helper, paramsValues, credentials) {
	this.helper = helper;
	this.loginUrl = paramsValues.get('Login URL');
	this.userName = credentials.getParam('Username');
	this.password = credentials.getParam('Password');

	return this;
}

MWAuthenticator.prototype = {
	doLogin: function (loginToken) {
		var requestBody = 'wpName=' + encodeURIComponent(this.userName) +
				'&wpPassword=' + encodeURIComponent(this.password) +
				'&wpLoginToken=' + encodeURIComponent(loginToken),
			response = this.doRequest(
				this.loginUrl + (this.loginUrl.indexOf('?') > -1 ? '&' : '?') + 'action=submitlogin&type=login',
				HttpRequestHeader.POST,
				requestBody
			);

		return response;
	},

	getLoginToken: function () {
		var response = this.doRequest(this.loginUrl, HttpRequestHeader.GET),
			loginToken = this.getLoginTokenFromForm(response, 'wpLoginToken');

		return loginToken;
	},

	doRequest: function (url, requestMethod, requestBody) {
		var msg,
			requestInfo,
			requestUri = new URI(url, false),
			requestHeader = new HttpRequestHeader(requestMethod, requestUri, HttpHeader.HTTP10);

		requestInfo = 'Sending ' + requestMethod + ' request to ' + requestUri;
		msg = this.helper.prepareMessage();
		msg.setRequestHeader(requestHeader);

		if (requestBody) {
			requestInfo += ' with body: ' + requestBody;
			msg.setRequestBody(requestBody);
		}
		msg.getRequestHeader().setContentLength(msg.getRequestBody().length());

		print(requestInfo);
		this.helper.sendAndReceive(msg);
		print("Received response status code for authentication request: " + msg.getResponseHeader().getStatusCode());

		return msg;
	},

	getLoginTokenFromForm: function (request, loginTokenName) {
		var iterator, element, loginToken,
			pageSource = request.getResponseHeader().toString() + request.getResponseBody().toString(),
			src = new Source(pageSource),
			elements = src.getAllElements('input');

		for (iterator = elements.iterator(); iterator.hasNext();) {
			element = iterator.next();
			if (element.getAttributeValue('name') == 'wpLoginToken') {
				loginToken = element.getAttributeValue('value');
				break;
			}
		}

		return loginToken;
	}
};
