import groovy.transform.Field
import org.parosproxy.paros.extension.AbstractPanel
import org.parosproxy.paros.view.WorkbenchPanel
import org.zaproxy.zap.ZAP
import org.zaproxy.zap.extension.scripts.ExtenderScriptHelper
import org.zaproxy.zap.utils.DisplayUtils

import javax.swing.ImageIcon
import javax.swing.JLabel

// Adds example select, status and work panels
// Extender scripts allow you to add completely new functionality to ZAP.
// The install function is called when the script is enabled and the uninstall function when it is disabled.
// Any functionality added in the install function should be removed in the uninstall method.
// See the other templates for examples on how to do add different functionality.

// Script variable to use when unregistering
@Field final AbstractPanel selectpanel = new AbstractPanel()
@Field final AbstractPanel statuspanel = new AbstractPanel()
@Field final AbstractPanel workpanel = new AbstractPanel()

/**
 * This function is called when the script is enabled.
 *
 * @param helper -  a helper class which provides 2 methods:
 *                  getView()   this returns a View object which provides an easy way to add graphical elements.
 *                              It will be null is ZAP is running in daemon mode.
 *                  getApi()    this returns an API object which provides an easy way to add new API calls.
 *                              Links to any functionality added should be held in script variables so that they can be removed in uninstall.
 */
void install(ExtenderScriptHelper helper) {
    if (helper.getView()) {
        // The icons bundled with ZAP are listed here https://github.com/zaproxy/zaproxy/tree/main/zap/src/main/resources/resource
        selectpanel.setName('Select Example')
        selectpanel.setIcon(DisplayUtils.getScaledIcon(
                new ImageIcon(ZAP.class.getResource("/resource/icon/16/035.png"))))
        selectpanel.add(new JLabel("TODO - add more stuff here"));
        helper.getView().getMainFrame().getWorkbench().addPanel(selectpanel, WorkbenchPanel.PanelType.SELECT)
        // Set the focus just so that it appears - otherwise people might think it hasnt worked ;)
        selectpanel.setTabFocus()

        statuspanel.setName('Status Example')
        statuspanel.setIcon(DisplayUtils.getScaledIcon(
                new ImageIcon(ZAP.class.getResource("/resource/icon/16/035.png"))))
        statuspanel.add(new JLabel("TODO - add more stuff here"));
        helper.getView().getMainFrame().getWorkbench().addPanel(statuspanel, WorkbenchPanel.PanelType.STATUS)
        // Set the focus just so that it appears - otherwise people might think it hasnt worked ;)
        statuspanel.setTabFocus()

        workpanel.setName('Work Example')
        workpanel.setIcon(DisplayUtils.getScaledIcon(
                new ImageIcon(ZAP.class.getResource("/resource/icon/16/035.png"))));
        workpanel.add(new JLabel("TODO - add more stuff here"));
        helper.getView().getMainFrame().getWorkbench().addPanel(workpanel, WorkbenchPanel.PanelType.WORK)
        // Set the focus just so that it appears - otherwise people might think it hasnt worked ;)
        workpanel.setTabFocus()

    }
}

/**
 * This function is called when the script is disabled.
 *
 * @param helper -  a helper class which provides 2 methods:
 *                  getView()   this returns a View object which provides an easy way to add graphical elements.
 *                              It will be null is ZAP is running in daemon mode.
 *                  getApi()    this returns an API object which provides an easy way to add new API calls.
 */
void uninstall(ExtenderScriptHelper helper) {
    if (helper.getView()) {
        helper.getView().getMainFrame().getWorkbench().removePanel(selectpanel, WorkbenchPanel.PanelType.SELECT)
        helper.getView().getMainFrame().getWorkbench().removePanel(statuspanel, WorkbenchPanel.PanelType.STATUS)
        helper.getView().getMainFrame().getWorkbench().removePanel(workpanel, WorkbenchPanel.PanelType.WORK)
    }
}
