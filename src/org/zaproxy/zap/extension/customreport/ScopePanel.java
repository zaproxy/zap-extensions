package org.zaproxy.zap.extension.customreport;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;


public class ScopePanel extends AbstractPanel{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	private JTextArea name, description;
	private JComboBox template;
	private JCheckBox onlyInScope;
	
	public ScopePanel(){
		initialize();
	}
	
	private void initialize(){
        this.setLayout( new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(2,3,2,3);
        
        // name line 
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
		this.add( new JLabel(Constant.messages.getString("customreport.scopepanel.name")), gbc );
		
		gbc.gridx++ ;
		name = new JTextArea(Constant.messages.getString("customreport.scopepanel.report"));
		this.add( new JScrollPane(name, JScrollPane.VERTICAL_SCROLLBAR_NEVER,JScrollPane.HORIZONTAL_SCROLLBAR_NEVER), gbc );
        
        // description line 
        gbc.gridy++ ;
        gbc.gridx = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        this.add( new JLabel(Constant.messages.getString("customreport.scopepanel.description")), gbc );
 
        gbc.gridx++;
		description = new JTextArea(Constant.messages.getString("customreport.scopepanel.desc"), 3, 30 );
		description.setLineWrap( true );
        this.add( new JScrollPane( description ), gbc );
        
        // template line
        gbc.gridx = 0 ;
        gbc.gridy++;
        gbc.anchor = GridBagConstraints.WEST;
	    this.add( new JLabel(Constant.messages.getString("customreport.scopepanel.template")), gbc );
	    
	    String[] selection = {Constant.messages.getString("customreport.scopepanel.template.traditional"), 
	    		              Constant.messages.getString("customreport.scopepanel.template.separated"), 
	    		              Constant.messages.getString("customreport.scopepanel.template.concise")};
	    template = new JComboBox<>( selection );
	    template.setSelectedIndex(0);
	    gbc.gridx++;
	    gbc.anchor = GridBagConstraints.EAST;
	    this.add( template, gbc );
	    
	    // just alert check box line 
	    gbc.gridx = 0;
	    gbc.gridy++;
	    gbc.anchor = GridBagConstraints.WEST;
	    this.add( new JLabel(Constant.messages.getString("customreport.scopepanel.scope")), gbc );
	    
	    onlyInScope = new JCheckBox();
        gbc.gridx++;
        gbc.anchor = GridBagConstraints.EAST;
        this.add( onlyInScope, gbc );

	}
	
	public String getReportName(){
		return name.getText();
	}
	
	public String getReportDescription(){
		return description.getText();
	}
	
	public boolean onlyInScope(){
		return onlyInScope.isSelected();
	}
	
	public String getTemplate(){
		return (String)template.getSelectedItem();
	}
		
}
