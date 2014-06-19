package org.zaproxy.zap.extension.soap;

import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Point;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JTextField;

public class ImportFromUrlDialog extends JDialog implements ActionListener{

	/**
	 * 
	 */
	private static final long serialVersionUID = -7074394202143400215L;

	private ExtensionImportWSDL caller = null;
	
	private JLabel labelURL = new JLabel("URL pointing to .wsdl file: ");
    private JTextField fieldURL = new JTextField(30);
    
    private JButton buttonImport = new JButton("Import");
    
    public ImportFromUrlDialog(JFrame parent, ExtensionImportWSDL caller){	
    	super(parent, "Import WSDL file from URL", true);
    	if (caller != null){
    		this.caller = caller;
    	}
    	if (parent != null) {
	      Dimension parentSize = parent.getSize(); 
	      Point p = parent.getLocation(); 
	      setLocation(p.x + parentSize.width / 4, p.y + parentSize.height / 4);
	    }
    	// set up layout
        setLayout(new GridBagLayout());
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.anchor = GridBagConstraints.WEST;
        constraints.insets = new Insets(5, 5, 5, 5);
        
        buttonImport.addActionListener(this);
        
        // add components to the frame
        constraints.gridx = 0;
        constraints.gridy = 0;
        add(labelURL, constraints);
 
        constraints.gridx = 1;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.weightx = 1.0;
        add(fieldURL, constraints);
        
        constraints.gridy = 2;
        constraints.anchor = GridBagConstraints.CENTER;
        add(buttonImport, constraints);
        
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        pack(); 
        setVisible(true);
    }
    
    /* Action executed by import button. */
    public void actionPerformed(ActionEvent e) {
    	if (caller != null){
    		String url = fieldURL.getText();
    		/* Calls a parsing task in a new thread. */
    		caller.extUrlWSDLImport(url, true);
    	}
        setVisible(false); 
        dispose(); 
    }
    
}
