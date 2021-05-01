// Adds example select, status and work panels
// Extender scripts allow you to add completely new functionality to ZAP.
// The install function is called when the script is enabled and the uninstall function when it is disabled.
// Any functionality added in the install function should be removed in the uninstall method.
// See the other templates for examples on how to do add different functionality. 

// Script variable to use when unregistering
var jlabel = Java.type("javax.swing.JLabel");
var paneltype = Java.type("org.parosproxy.paros.view.WorkbenchPanel.PanelType");
var abstractpanel = Java.type("org.parosproxy.paros.extension.AbstractPanel");
var selectpanel = new abstractpanel()
var statuspanel = new abstractpanel()
var workpanel = new abstractpanel()

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
    // The icons bundled with ZAP are listed here https://github.com/zaproxy/zaproxy/tree/main/zap/src/main/resources/resource
    var imageicon = Java.type("javax.swing.ImageIcon");
    selectpanel.setName('Select Example')
    selectpanel.setIcon(org.zaproxy.zap.utils.DisplayUtils.getScaledIcon(
       new imageicon(org.zaproxy.zap.ZAP.class.getResource("/resource/icon/16/035.png"))));
    selectpanel.add(new jlabel("TODO - add more stuff here"));
    helper.getView().getMainFrame().getWorkbench().addPanel(selectpanel, paneltype.SELECT)
    // Set the focus just so that it appears - otherwise people might think it hasnt worked ;)
    selectpanel.setTabFocus()

    statuspanel.setName('Status Example')
    statuspanel.setIcon(org.zaproxy.zap.utils.DisplayUtils.getScaledIcon(
       new imageicon(org.zaproxy.zap.ZAP.class.getResource("/resource/icon/16/035.png"))));
    statuspanel.add(new jlabel("TODO - add more stuff here"));
    helper.getView().getMainFrame().getWorkbench().addPanel(statuspanel, paneltype.STATUS)
    // Set the focus just so that it appears - otherwise people might think it hasnt worked ;)
    statuspanel.setTabFocus()

    workpanel.setName('Work Example')
    workpanel.setIcon(org.zaproxy.zap.utils.DisplayUtils.getScaledIcon(
       new imageicon(org.zaproxy.zap.ZAP.class.getResource("/resource/icon/16/035.png"))));
    workpanel.add(new jlabel("TODO - add more stuff here"));
    helper.getView().getMainFrame().getWorkbench().addPanel(workpanel, paneltype.WORK)
    // Set the focus just so that it appears - otherwise people might think it hasnt worked ;)
    workpanel.setTabFocus()

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
    helper.getView().getMainFrame().getWorkbench().removePanel(selectpanel, paneltype.SELECT);
    helper.getView().getMainFrame().getWorkbench().removePanel(statuspanel, paneltype.STATUS);
    helper.getView().getMainFrame().getWorkbench().removePanel(workpanel, paneltype.WORK);
  }
}
