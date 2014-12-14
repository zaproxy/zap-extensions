package org.parosproxy.paros.extension.advreport;

import javax.swing.JTabbedPane;

import org.parosproxy.paros.view.AbstractFrame;

public class OptionDialog extends AbstractFrame{
	
	public OptionDialog( ScopePanel scopeponel, AdvancedPanel advancedpanel){
		JTabbedPane mainpane = new JTabbedPane();
        mainpane.add("Scope", scopeponel );
        mainpane.add("Advanced", advancedpanel );
        this.setTitle("Generate report");
        this.add(mainpane);
        this.pack();
	}
}
