/*
Input Vectors Script for injecting inline arguments in GraphQL queries proxied through ZAP.
*/

var injector = new (Java.type('org.zaproxy.addon.graphql.InlineInjector'))();

function getQuery(msg){
	var header = msg.getRequestHeader();
	var body = msg.getRequestBody().toString();
	var query;
	
	if (header.getMethod() == "POST") {
		var contentTypeHeader = header.getHeader("Content-Type");
		if (contentTypeHeader == null || contentTypeHeader.contains("application/json")) {
			try{
				var json = JSON.parse(body);
				query = json.query;
			}
			catch(err){
				print("Parsing message body failed: " + err.message);
				return null;
			}
		} else if (contentTypeHeader.contains("application/graphql")) {
			query = body;
		}
	} else if (header.getMethod() == "GET") {
		msg.getUrlParams().forEach(function(param) {
			if (param.getName() == 'query') {
				query = param.getValue()
			}
		});
	}
	return injector.validateQuery(query) ? query : null;
}

function setQuery(msg, query){
	var header = msg.getRequestHeader();
	var body = msg.getRequestBody().toString();
	
	if (header.getMethod() == "POST") {
		var contentTypeHeader = header.getHeader("Content-Type");
		if (contentTypeHeader == null || contentTypeHeader.contains("application/json")) {
			try{
				var json = JSON.parse(body);
				json.query = query;
				msg.setRequestBody(JSON.stringify(json));
				msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
			}
			catch(err){
				print("Parsing message body failed: " + err.message);
			}
		} else if (contentTypeHeader.contains("application/graphql")) {
			msg.setRequestBody(query);
			msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
		}
	} else if (header.getMethod() == "GET") {
		msg.getUrlParams().forEach(function(param) {
			if (param.getName() == 'query') {
				param.setValue(query);
			}
		});
	}
}

function parseParameters(helper, msg) {
	var query = getQuery(msg);
	if (query == null) {
		// print("  not GraphQL");
		return;	
	}
	var params = injector.extract(query);
	var NameValuePair = Java.type("org.parosproxy.paros.core.scanner.NameValuePair");
	params.forEach(function(name, value){
		helper.addParam(name, value, NameValuePair.TYPE_GRAPHQL_INLINE);
	})
}

function setParameter(helper, msg, param, value, escaped) {
	var query = getQuery(msg);
	if (query == null) {
		// print("  not GraphQL");
		return;	
	}
	try {
		setQuery(msg, injector.inject(query, param, JSON.stringify(value)));	
	} catch(err){
		print("Setting Paramater failed: " + err.message);
		return;
	}
}

function getLeafName(helper, nodeName, msg) {
	parseParameters(helper, msg)
	if (helper.getParamList().isEmpty()) {
		return null;
	}
	return helper.getStandardLeafName(nodeName, msg, helper.getParamList())
}


function getTreePath(helper, msg) {
	var query = getQuery(msg);
	if (query == null) {
		// print("  not GraphQL");
		return null;	
	}
	var uri = msg.getRequestHeader().getURI();
	var path = uri.getPath() != null ? uri.getPath().split('/') : [];
	var list = [];
	for (var x = 1; x < path.length; x++) {
		list.push(path[x]);
	}
	list.push(injector.extractOperations(query));
	list.push(injector.getNodeName(query));
	return list;
}
