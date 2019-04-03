// Adds an example history record menu - this is often shown when a url is right clicked, for example in the History table
// Extender scripts allow you to add completely new functionality to ZAP.
// The install function is called when the script is enabled and the uninstall function when it is disabled.
// Any functionality added in the install function should be removed in the uninstall method.
// See the other templates for examples on how to do add different functionality. 

// Script variable to use when uninstalling
var popupmenuitemtype = Java.type("org.zaproxy.zap.view.popup.PopupMenuItemHistoryReferenceContainer");
var menuitem = new popupmenuitemtype("Example history reference menu") {
      performAction: function(href) {
        print("Example menu called with " + href.getHttpMessage().getRequestHeader().getURI().toString());
        view.showMessageDialog(
          "Example menu called with " + href.getHttpMessage().getRequestHeader().getURI().toString());
      }
    }

// View to be used in the menu item (initialised when installing the script).
var view;

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
    helper.getView().getPopupMenu().addMenu(menuitem);
    view = helper.getView();
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
    helper.getView().getPopupMenu().removeMenu(menuitem);
  }
}
