/*
Script for representing each SOAP operation uniquely in the Sites Tree.
*/

function parseParameters(helper, msg) { }

function setParameter(helper, msg, param, value, escaped) { }

function getLeafName(helper, nodeName, msg) {
	if (helper.getParamList().isEmpty()) {
		return null;
	}
	return helper.getStandardLeafName(nodeName, msg, helper.getParamList());
}

function getTreePath(helper, msg) {
	var nodeName = Java.type('org.zaproxy.zap.extension.soap.SitesTreeHelper').getNodeName(msg);
	if (nodeName == '') {
		// Not a SOAP message
		return null;
	}
	var uri = msg.getRequestHeader().getURI();
	var path = uri.getPath() != null ? uri.getPath().split('/') : [];
	var list = [];
	for (var x = 1; x < path.length; x++) {
		list.push(path[x]);
	}
	list.push(nodeName);
	return list;
}
