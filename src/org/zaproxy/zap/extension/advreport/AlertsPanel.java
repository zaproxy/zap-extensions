package org.zaproxy.zap.extension.advreport;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import org.parosproxy.paros.core.scanner.Alert;


public class AlertsPanel extends JPanel{

	private List<JCheckBox> selections;
	private ExtensionAdvReport extension;
	
	public static final String[] MSG_RISK = Alert.MSG_RISK;
	
	private Map<String, Integer> AlertTypeRisk = null;
	
	public AlertsPanel(List<String> alertTypes,ExtensionAdvReport extension){
		initialize(alertTypes);
		this.extension = extension;
		AlertTypeRisk = extension.AlertTypeRisk;
	}

	private void initialize( List<String> alertTypes ){
		
        selections = new ArrayList<JCheckBox>();
        //Alert selection Panel
		JPanel selectionPanel = new JPanel();
		selectionPanel.setLayout( new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridx = 0;
		gbc.gridy = 0;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		gbc.insets = new Insets(2,5,30,10);
		
		selectionPanel.add(getRiskBox("High"), gbc);
		
		gbc.gridx++;
		selectionPanel.add(getRiskBox("Medium"),gbc);
		
		gbc.gridx++;
		selectionPanel.add(getRiskBox("Low"),gbc);
		
		gbc.gridx++;
		selectionPanel.add(getRiskBox("Informational"),gbc);
		
		gbc.insets = new Insets(0,20,2,0);
		gbc.gridy = 1;
		gbc.gridwidth = 4;
		
		for( String alertType: alertTypes ){
			
		    JCheckBox selection = new JCheckBox();
		    selection.setText(alertType);
		    selection.setSelected( true );
		    selection.setName( alertType );
		    
		    gbc.gridx = 0;
		    gbc.anchor = GridBagConstraints.CENTER;
		    selectionPanel.add(selection, gbc);
		    this.getSelections().add( selection );	
			gbc.gridy += 1;
			
		}
		 				
        JPanel buttonpane = new JPanel( new FlowLayout( FlowLayout.RIGHT ));
        buttonpane.add( getCancelButton() );
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
	
	
	private JCheckBox getRiskBox(final String riskLevel){
		JCheckBox riskChk = new JCheckBox();
		riskChk.setText(riskLevel);
		riskChk.setSelected(true);
		riskChk.addItemListener(new java.awt.event.ItemListener() {
			@Override
			public void itemStateChanged(java.awt.event.ItemEvent e) {
				boolean selected = (ItemEvent.SELECTED == e.getStateChange());
				for (JCheckBox selection: selections ){
					if(MSG_RISK[AlertTypeRisk.get(selection.getName())] == riskLevel) {
						selection.setSelected(selected);
					}

				}
			}
		});
		
		return riskChk;
	}
	
	private JButton getCancelButton(){
		JButton cancelbutton = new JButton("Cancel");
		cancelbutton.addActionListener(
				new ActionListener() {
		            @Override
		            public void actionPerformed(ActionEvent e) {
		               extension.emitFrame();
		            }
		        });
		return cancelbutton;
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