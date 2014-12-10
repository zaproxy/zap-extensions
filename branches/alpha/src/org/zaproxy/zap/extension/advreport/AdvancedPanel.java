package org.zaproxy.zap.extension.advreport;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;


public class AdvancedPanel extends JPanel{

	private List<JCheckBox> selections;
	private ExtensionAdvReport extension;
	
	public AdvancedPanel(List<String> alertTypes,ExtensionAdvReport extension){
		initialize(alertTypes);
		this.extension = extension;
	}

	private void initialize( List<String> alertTypes ){
		
		// generate and ad labels
        selections = new ArrayList<JCheckBox>();
        
		JPanel selectionPanel = new JPanel();
		selectionPanel.setLayout( new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridx = 0;
		gbc.gridy = 0;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		for( String alertType: alertTypes ){
			JLabel label = new JLabel(alertType);
		    JCheckBox selection = new JCheckBox();
		    selection.setSelected( true );
		    selection.setName( alertType );
		    
		    gbc.gridx = 0;
		    gbc.anchor = GridBagConstraints.WEST;
		    selectionPanel.add(label, gbc);
			
		    gbc.gridx = 1;
		    gbc.anchor = GridBagConstraints.EAST;
		    selectionPanel.add(selection, gbc);
		    this.getSelections().add( selection );	
			
			gbc.gridy += 1;
		}
		
        JPanel buttonpane = new JPanel( new FlowLayout( FlowLayout.RIGHT ));
        buttonpane.add( getCancleButton() );
        buttonpane.add( getHTMLButton() );
        
		this.setLayout( new BorderLayout() );
		this.add( new JLabel(" Alerts in Report : " ), BorderLayout.NORTH );
		this.add( new JScrollPane( selectionPanel ), BorderLayout.CENTER );
        this.add(buttonpane, BorderLayout.SOUTH);
		
		
	}
	
	private List<JCheckBox> getSelections(){
		if( selections == null ){
			selections = new ArrayList<JCheckBox>();
		}
		return selections;
	}
	
	public List<String> getSelectedAlerts(){
		List<String> selectedAlerts = new ArrayList<String>();
		for( JCheckBox selection: selections ){
			if( selection.isSelected() ) selectedAlerts.add( selection.getName());
		}
		return selectedAlerts;
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

