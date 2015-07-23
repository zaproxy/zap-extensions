package org.zaproxy.zap.extension.advreport;

import javax.swing.JTabbedPane;

import org.parosproxy.paros.view.AbstractFrame;

public class OptionDialog extends AbstractFrame{
	
	public OptionDialog( ScopePanel scopepanel, AlertsPanel alertspanel, AlertDetailsPanel alertdetailspanel ){
		JTabbedPane mainpane = new JTabbedPane();
        mainpane.add("Scope", scopepanel );
        mainpane.add("Alerts", alertspanel );
        mainpane.add("Alert Details", alertdetailspanel );
        this.setTitle("Generate report");
        this.add(mainpane);
        this.pack();
	}
}
