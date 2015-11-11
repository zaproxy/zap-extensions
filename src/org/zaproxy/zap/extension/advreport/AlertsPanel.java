package org.zaproxy.zap.extension.advreport;
import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ItemEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import org.parosproxy.paros.Constant;


public class AlertsPanel extends JPanel{

	private List<JCheckBox> selections;

	private Map<String, String> alertTypeRisk = null;
	//Alert types with corresponding risk Levels (High, Medium, Low, Informational)
	public AlertsPanel(List<String> alertTypes,ExtensionAdvReport extension){
		initialize(alertTypes);
		alertTypeRisk = extension.alertTypeRisk;
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
		
		selectionPanel.add(getRiskBox(Constant.messages.getString("advreport.alertspanel.risk.high"), "High"), gbc);
		
		gbc.gridx++;
		selectionPanel.add(getRiskBox(Constant.messages.getString("advreport.alertspanel.risk.medium"), "Medium"),gbc);
		
		gbc.gridx++;
		selectionPanel.add(getRiskBox(Constant.messages.getString("advreport.alertspanel.risk.low"), "Low"),gbc);
		
		gbc.gridx++;
		selectionPanel.add(getRiskBox(Constant.messages.getString("advreport.alertspanel.risk.info"), "Informational"),gbc);
		
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
        
		this.setLayout( new BorderLayout() );
		this.add( new JLabel(Constant.messages.getString("advreport.alertspanel.label") ), BorderLayout.NORTH );
		this.add( new JScrollPane( selectionPanel ), BorderLayout.CENTER );
		
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
	
	
	private JCheckBox getRiskBox(final String riskLevel, final String riskName){
		JCheckBox riskChk = new JCheckBox();
		riskChk.setText(riskLevel);
		riskChk.setSelected(true);
		riskChk.addItemListener(new java.awt.event.ItemListener() {
			@Override
			public void itemStateChanged(java.awt.event.ItemEvent e) {
				boolean selected = (ItemEvent.SELECTED == e.getStateChange());
				for (JCheckBox selection: selections ){
					if(alertTypeRisk.get(selection.getName()) == riskName) {
						selection.setSelected(selected);
					}

				}
			}
		});
		
		return riskChk;
	}
		
}
