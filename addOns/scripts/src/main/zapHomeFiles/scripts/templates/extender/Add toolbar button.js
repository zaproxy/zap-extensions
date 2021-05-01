// Adds a button to the main toolbar. Pressing on the button shows a new window.
// Extender scripts allow you to add completely new functionality to ZAP.
// The install function is called when the script is enabled and the uninstall function when it is disabled.
// Any functionality added in the install function should be removed in the uninstall method.
// See the other templates for examples on how to do add different functionality. 

// Script variable to use when uninstalling
var jbutton = Java.type("javax.swing.JButton");
var button = new jbutton();

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
    var imageicon = Java.type("javax.swing.ImageIcon");
    // The icons bundled with ZAP are listed here https://github.com/zaproxy/zaproxy/tree/main/zap/src/main/resources/resource
    button.setIcon(org.zaproxy.zap.utils.DisplayUtils.getScaledIcon(
       new imageicon(org.zaproxy.zap.ZAP.class.getResource("/resource/icon/16/035.png"))));
    button.setToolTipText("An example button");
    button.addActionListener(new java.awt.event.ActionListener() {
        actionPerformed: function(event) {
            print("Example button pressed");
            create_window();
        }
    });
    helper.getView().addMainToolbarButton(button)
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
    // If revalidate isnt called then the button appear to stay on the toolbar
    helper.getView().getMainFrame().getMainToolbarPanel().revalidate();
    helper.getView().removeMainToolbarButton(button);
  }
}

function create_window() {
  // based on https://github.com/zaproxy/community-scripts/blob/master/standalone/window_creation_template.js
  var absframe = Java.type("org.parosproxy.paros.view.AbstractFrame");
  var jpanel = Java.type("javax.swing.JPanel");
  var jlabel = Java.type("javax.swing.JLabel");
  var jmenubar = Java.type("javax.swing.JMenuBar");
  var jmenu = Java.type("javax.swing.JMenu");
  var jmenuitem = Java.type("javax.swing.JMenuItem");
  var window = new absframe(){};
  window.setAlwaysOnTop(false);
  window.setSize(500, 500);
  var menubar = new jmenubar();
  var menu = new jmenu("A Menu");
  var menu_ac = menu.getAccessibleContext();
  menu_ac.setAccessibleDescription("The only menu in this program");
  var menuitem = new jmenuitem("A Menu Item");
  menu.add(menuitem);
  menubar.add(menu);
  window.setJMenuBar(menubar);
  var lbl = new jlabel("A Label");
  lbl.setHorizontalAlignment(jlabel.CENTER);
  lbl.setVerticalAlignment(jlabel.CENTER);
  window.setContentPane(lbl);
  window.setVisible(true);
}
