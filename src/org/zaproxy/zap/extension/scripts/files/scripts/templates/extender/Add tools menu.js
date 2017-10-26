// Add an example tool bar menu
// Extender scripts allow you to add completely new functionality to ZAP.
// The install function is called when the script is enabled and the uninstall function when it is disabled.
// Any functionality added in the install function should be removed in the uninstall method.
// See the other templates for examples on how to do add different functionality. 

// The following handles differences in printing between Java 7's Rhino JS engine
// and Java 8's Nashorn JS engine
if (typeof println == 'undefined') this.println = print;

// Script variable to use when uninstalling
var menuitem

/**
 * This function is called when the script is enabled.
 * 
 * @param helper - a helper class which provides 2 methods:
 *		getView() this returns a View object which provides an easy way to add graphical elements.
 *		It will be null is ZAP is running in daemon mode.
 *		getApi() this returns an API object which provides an easy way to add new API calls.
 *	Links to any functionality added should be held in script variables so that they can be removed in uninstall.
 */
function install(helper) {
  if (helper.getView()) {
    var jmenuitem = Java.type("javax.swing.JMenuItem");
    menuitem = new jmenuitem("A menu item");
    menuitem.addActionListener(function(event) {
      print("Example menu selected");
      ans = helper.getView().showYesNoCancelDialog('Are you sure?')
      if (ans == 0) {
        print("Yes, they really mean it :)")
      } else if (ans == 1) {
        print("No, they're not sure :(")
      } else if (ans == 2) {
        print("They canceled :/")
      }
    });
    helper.getView().getMainFrame().getMainMenuBar().getMenuTools().add(menuitem);
  }
}

/**
 * This function is called when the script is disabled.
 * 
 * @param helper - a helper class which provides 2 methods:
 *		getView() this returns a View object which provides an easy way to add graphical elements.
 *		It will be null is ZAP is running in daemon mode.
 *		getApi() this returns an API object which provides an easy way to add new API calls.
 */
function uninstall(helper) {
  if (helper.getView()) {
    helper.getView().getMainFrame().getMainMenuBar().getMenuTools().remove(menuitem);
  }
}
