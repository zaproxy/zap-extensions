// Extender scripts allow you to add completely new functionality to ZAP.
// The install function is called when the script is enabled and the uninstall function when it is disabled.
// Any functionality added in the install function should be removed in the uninstall method.
// See the other templates for examples on how to do add different functionality. 

// Script variable to use when uninstalling
var popupmenuitemtype = Java.type("org.zaproxy.zap.view.popup.PopupMenuItemHistoryReferenceContainer");
var curlmenuitem = new popupmenuitemtype("Copy as curl command") {
	performAction: function(href) {
		invokeWith(href.getHttpMessage());
	}
}

/**
 * This function is called when the script is enabled.
 * 
 * @param helper - a helper class which provides the methods:
 *		getView() this returns a View object which provides an easy way to add graphical elements.
 *			It will be null is ZAP is running in daemon mode.
 *		getApi() this returns an API object which provides an easy way to add new API calls.
 *	Links to any functionality added should be held in script variables so that they can be removed in uninstall.
 */
function install(helper) {
	if (helper.getView()) {
		helper.getView().getPopupMenu().addMenu(curlmenuitem);
	}
}

/**
 * This function is called when the script is disabled.
 * 
 * @param helper - a helper class which provides the methods:
 *		getView() this returns a View object which provides an easy way to add graphical elements.
 *			It will be null is ZAP is running in daemon mode.
 *		getApi() this returns an API object which provides an easy way to add new API calls.
 */
function uninstall(helper) {
  if (helper.getView()) {
    helper.getView().getPopupMenu().removeMenu(curlmenuitem);
  }
}

function invokeWith(msg) {
	string = "curl -i -s -k -X  '"+msg.getRequestHeader().getMethod()+"'  \\\n";
	header = msg.getRequestHeader().getHeadersAsString();
	header = header.split(msg.getRequestHeader().getLineDelimiter());
	for(i=0;i<header.length;i++){
		// deny listing Host (other deny listing should also specify here)
		keyval = header[i].split(":");
		if(keyval[0].trim() != "Host")
			string += " -H '"+header[i].trim()+"' ";
	}
	string += " \\\n";
	body = msg.getRequestBody().toString();
	if(body.length() != 0){
		string += "--data-binary $'"+addSlashes(body)+"' \\\n";
	}
	string += "'"+msg.getRequestHeader().getURI().toString()+"'";
	selected = new java.awt.datatransfer.StringSelection(string);
	clipboard = java.awt.Toolkit.getDefaultToolkit().getSystemClipboard();
	clipboard.setContents(selected,null);
	print (string);
}

function addSlashes(body){
	var a ={}
	a[body] = 1;
	return JSON.stringify(a).slice(2,-4);
}
