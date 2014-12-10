package org.parosproxy.paros.extension.advreport;

import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import org.parosproxy.paros.extension.AbstractPanel;


public class ScopePanel extends AbstractPanel{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	private ExtensionAdvReport extension = null;
	private JTextArea name, description;
	private JComboBox template;
	private JCheckBox onlyInScope;
	
	public ScopePanel( ExtensionAdvReport extension){
		initialize();
		this.extension = extension;
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
		this.add( new JLabel("Name : "), gbc );
		
		gbc.gridx++ ;
		name = new JTextArea(" Report ");
		this.add( new JScrollPane(name, JScrollPane.VERTICAL_SCROLLBAR_NEVER,JScrollPane.HORIZONTAL_SCROLLBAR_NEVER), gbc );
        
        // description line 
        gbc.gridy++ ;
        gbc.gridx = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        this.add( new JLabel("Description :¡¡"), gbc );
 
        gbc.gridx++;
		description = new JTextArea( " Description ", 3, 30 );
		description.setLineWrap( true );
        this.add( new JScrollPane( description ), gbc );
        
        // template line
        gbc.gridx = 0 ;
        gbc.gridy++;
        gbc.anchor = GridBagConstraints.WEST;
	    this.add( new JLabel("Template : "), gbc );
	    
	    String[] selection = {"Traditional", "Separated Sites", "Concise" };
	    template = new JComboBox<>( selection );
	    template.setSelectedIndex(0);
	    gbc.gridx++;
	    gbc.anchor = GridBagConstraints.EAST;
	    this.add( template, gbc );
	    
	    // just alert check box line 
	    gbc.gridx = 0;
	    gbc.gridy++;
	    gbc.anchor = GridBagConstraints.WEST;
	    this.add( new JLabel("Only contents in scope?"), gbc );
	    
	    onlyInScope = new JCheckBox();
        gbc.gridx++;
        gbc.anchor = GridBagConstraints.EAST;
        this.add( onlyInScope, gbc );
	    
	    // button line 
        gbc.insets = new Insets(0,0,0,0);
	    gbc.gridx = 1;
        gbc.gridy++ ;
        JPanel buttonpane = new JPanel( new FlowLayout( FlowLayout.RIGHT ));
        buttonpane.add( getCancleButton() );
        buttonpane.add( getHTMLButton() );
        this.add( buttonpane, gbc );
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
	
	private JButton getCancleButton(){
		JButton canclebutton = new JButton("Cancle");
		canclebutton.addActionListener(
				new ActionListener() {
		            @Override
		            public void actionPerformed(ActionEvent e) {
		               extension.emitFrame();
		            }
		        });
		return canclebutton;
	}
	
	private JButton getHTMLButton(){
		JButton generatebutton = new JButton("Generate HTML");
		generatebutton.addActionListener(
				new ActionListener() {
		            @Override
		            public void actionPerformed(ActionEvent e) {
		                extension.generateReport();
		            }
		        });
		return generatebutton;
	}
	
	
	
}
