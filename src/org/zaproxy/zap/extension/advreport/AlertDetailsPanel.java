package org.zaproxy.zap.extension.advreport;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.Insets;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import org.parosproxy.paros.Constant;


public class AlertDetailsPanel extends JPanel{

	private ExtensionAdvReport extension;
	private JCheckBox description = null;
	private JCheckBox otherInfo = null;
	private JCheckBox solution = null;
	private JCheckBox reference = null;
	private JCheckBox cweid = null;
	private JCheckBox wascid = null;
	private JCheckBox requestHeader = null;
	private JCheckBox responseHeader = null;
	private JCheckBox requestBody = null;
	private JCheckBox responseBody = null;
	
	public AlertDetailsPanel(ExtensionAdvReport extension){
		initialize();
		this.extension = extension;
		description.setSelected(true);
		otherInfo.setSelected(true);
		solution.setSelected(true);
		reference.setSelected(true);
		cweid.setSelected(true);
		wascid.setSelected(true);	
	}

	private void initialize(){

		JPanel optionpanel = new JPanel();
		optionpanel.setLayout( new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();
		
		gbc.fill = GridBagConstraints.HORIZONTAL;
				
		//Include Description
	    description = new JCheckBox();
	    description.setText(Constant.messages.getString("advreport.alertdetails.description"));
	    gbc.gridy = 0;
	    gbc.gridx = 0;
	    gbc.anchor = GridBagConstraints.WEST;
	    gbc.insets = new Insets(2,0,2,100);
        optionpanel.add( description, gbc );
     
		//Include Other Info
		otherInfo = new JCheckBox();
		otherInfo.setText(Constant.messages.getString("advreport.alertdetails.otherinfo"));
        gbc.gridy++;
        optionpanel.add( otherInfo, gbc );
        
		//Include Solution  
	    solution = new JCheckBox();
	    solution.setText(Constant.messages.getString("advreport.alertdetails.solution"));
        gbc.gridy++;
        optionpanel.add( solution, gbc );
        
		//Include Reference	    
	    reference = new JCheckBox();
	    reference.setText(Constant.messages.getString("advreport.alertdetails.reference"));
        gbc.gridy++;
        optionpanel.add( reference, gbc );
        
		//Include CWE Id
	    cweid = new JCheckBox();
	    cweid.setText(Constant.messages.getString("advreport.alertdetails.cweid"));
        gbc.gridy++;
        optionpanel.add( cweid, gbc );
        
		//Include WASC ID
	    wascid= new JCheckBox();
	    wascid.setText(Constant.messages.getString("advreport.alertdetails.wascid"));
        gbc.gridy++;
        optionpanel.add( wascid, gbc );

		//Include Request Header
	    requestHeader = new JCheckBox();
	    requestHeader.setText(Constant.messages.getString("advreport.alertdetails.requestheader"));
        gbc.gridx = 1;
     	gbc.gridy = 0;
     	gbc.anchor = GridBagConstraints.EAST;
     	gbc.insets = new Insets(2,0,2,0);
        optionpanel.add( requestHeader, gbc );
        
		//Include Response Header
	    responseHeader = new JCheckBox();
	    responseHeader.setText(Constant.messages.getString("advreport.alertdetails.responseheader"));
        gbc.gridy++;
        optionpanel.add( responseHeader, gbc );
        
		//Include Request Body
	    requestBody = new JCheckBox();
        requestBody.setText(Constant.messages.getString("advreport.alertdetails.requestbody"));
	    gbc.gridy++;
        optionpanel.add( requestBody, gbc );
        
		//Include Response Body
	    responseBody = new JCheckBox();
	    responseBody.setText(Constant.messages.getString("advreport.alertdetails.responsebody"));
        gbc.gridy++;
        optionpanel.add( responseBody, gbc );

        JPanel buttonpane = new JPanel( new FlowLayout( FlowLayout.RIGHT ));
        buttonpane.add( getCancelButton() );
        buttonpane.add( getHTMLButton() );
        
		this.setLayout( new BorderLayout() );
		this.add( new JLabel(Constant.messages.getString("advreport.alertdetails.label")), BorderLayout.NORTH );
	    this.add( new JScrollPane( optionpanel ), BorderLayout.CENTER );
        this.add(buttonpane, BorderLayout.SOUTH);

	}
	
	public boolean description(){
		return description.isSelected();
	}
	
	public boolean otherInfo(){
		return otherInfo.isSelected();
	}
	
	public boolean solution(){
		return solution.isSelected();
	}
	
	public boolean reference(){
		return reference.isSelected();
	}
	
	public boolean cweid(){
		return cweid.isSelected();
	}
	
	public boolean wascid(){
		return wascid.isSelected();
	}
	
	public boolean requestHeader(){
		return requestHeader.isSelected();
	}
	
	public boolean responseHeader(){
		return responseHeader.isSelected();
	}
	
	public boolean requestBody(){
		return requestBody.isSelected();
	}
	
	public boolean responseBody(){
		return responseBody.isSelected();
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

