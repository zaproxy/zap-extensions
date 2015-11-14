package org.zaproxy.zap.extension.advreport;

import javax.swing.JTabbedPane;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.AbstractFrame;

public class OptionDialog extends AbstractFrame{
	
	public OptionDialog( ScopePanel scopepanel, AlertsPanel alertspanel, AlertDetailsPanel alertdetailspanel ){
		JTabbedPane mainpane = new JTabbedPane();
        mainpane.add(Constant.messages.getString("advreport.menu.scope"), scopepanel );
        mainpane.add(Constant.messages.getString("advreport.menu.alerts"), alertspanel );
        mainpane.add(Constant.messages.getString("advreport.menu.alertdetails"), alertdetailspanel );
        this.setTitle(Constant.messages.getString("advreport.menu.title"));
        this.add(mainpane);
        this.pack();
	}
}
