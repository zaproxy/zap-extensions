// Extender scripts allow you to add completely new functionality to ZAP.
// The install function is called when the script is enabled and the uninstall function when it is disabled.
// Any functionality added in the install function should be removed in the uninstall method.
// See the other templates for examples on how to do add different functionality. 

// Script variable to use when uninstalling
var popupmenuitemtype = Java.extend(Java.type("org.zaproxy.zap.view.popup.PopupMenuItemHistoryReferenceContainer"));
var curlmenuitem = new popupmenuitemtype("Copy as curl Command") {
	performAction: function(href) {
		invokeWith(href.getHttpMessage());
	},
	precedeWithSeparator: function() {
		return true;
	},
	isSafe: function() {
		return true;
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


// Note: The following code lives also in Community-Scripts add-on.

function invokeWith(msg) {
	var string = "curl -i -s -k -X  '"+msg.getRequestHeader().getMethod()+"'  \\\n";
	var header = msg.getRequestHeader().getHeadersAsString();
	header = header.split(msg.getRequestHeader().getLineDelimiter());
	var suspiciousHeaders = false;
	for(var i=0;i<header.length;i++){
		var headerEntry = header[i].trim()
		if (headerEntry.startsWith("@")) {
			suspiciousHeaders = true;
		}
		// deny listing Host (other deny listing should also specify here)
		var keyval = headerEntry.split(":");
		if(keyval[0].trim() != "Host")
			string += " -H '"+headerEntry+"' ";
	}
	// if no User-Agent present ensures that curl request doesn't add one
	if(string.indexOf("User-Agent") < 0)
		string += " -A '' ";
	string += " \\\n";
	var body = msg.getRequestBody().toString();
	if(body.length() != 0){
		string += "--data-raw $'"+addSlashes(body)+"' \\\n";
	}
	string += "'"+msg.getRequestHeader().getURI().toString()+"'";

	if (!suspiciousHeaders) {
		var selected = new java.awt.datatransfer.StringSelection(string);
		var clipboard = java.awt.Toolkit.getDefaultToolkit().getSystemClipboard();
		clipboard.setContents(selected,null);
	}
	print (string);

	if (suspiciousHeaders) {
		print("\n**WARNING**");
		print("The generated command might be including a local file (e.g. `@/path/to/file`) in a header, carefully review the command before executing it.");
		print("Note: The command was *not* added to the clipboard.\n");
	}
}

function addSlashes(body){
	var a ={}
	a[body] = 1;
	return JSON.stringify(a).slice(2,-4);
}
