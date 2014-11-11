package org.zaproxy.zap.extension.soap;

import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Point;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JTextField;

import org.parosproxy.paros.Constant;

public class ImportFromUrlDialog extends JDialog implements ActionListener{

	/**
	 * 
	 */
	private static final long serialVersionUID = -7074394202143400215L;
	private static final String MESSAGE_PREFIX = "soap.importfromurldialog.";

	private ExtensionImportWSDL caller = null;
	
	private JLabel labelURL = new JLabel(Constant.messages.getString(MESSAGE_PREFIX+"labelURL"));
    private JTextField fieldURL = new JTextField(30);
    
    private JButton buttonImport = new JButton(Constant.messages.getString(MESSAGE_PREFIX+"importButton"));
    
    public ImportFromUrlDialog(JFrame parent, ExtensionImportWSDL caller){	
    	super(parent, Constant.messages.getString(MESSAGE_PREFIX+"actionName"), true);
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
        fieldURL = addContextMenu(fieldURL);
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
    		caller.extUrlWSDLImport(url);
    	}
        setVisible(false); 
        dispose(); 
    }
    
    /* Adds a context menu to URL text field with "paste" option. */
    public JTextField addContextMenu(final JTextField field){
    	JTextField field2 = field;
    	field2.addMouseListener(new MouseAdapter(){
    	    public void mouseReleased(MouseEvent e){  
    	        if (e.isPopupTrigger()){  
    	        	JPopupMenu jPopupMenu = new JPopupMenu();  
    	        	String actionName = Constant.messages.getString(MESSAGE_PREFIX+"pasteaction");
    	            @SuppressWarnings("serial")
					Action pasteAction = new AbstractAction(actionName){  
    	                public void actionPerformed(ActionEvent e){   
    	                    field.paste();  
    	                }  
    	            };  
    	            JMenuItem paste = new JMenuItem(pasteAction);  
    	            jPopupMenu.add(paste);  
    	            jPopupMenu.show(field, e.getX(), e.getY());  
    	        }  
    	    }  
    	});
    	return field2;
    }
}
