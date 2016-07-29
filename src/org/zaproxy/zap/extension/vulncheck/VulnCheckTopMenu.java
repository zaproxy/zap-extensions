package org.zaproxy.zap.extension.vulncheck;

import java.util.ResourceBundle;

import javax.swing.JMenuItem;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;

public class VulnCheckTopMenu extends ExtensionAdaptor {

	
	private JMenuItem menuExample = null;
	private ResourceBundle messages = null;
	private String author = "ZAP-TEAM";
	@Override
	public String getAuthor() {
		return author;
	}
	
	public VulnCheckTopMenu() {
        super("VulnCheckTopMenu");
        // Load extension specific language files - these are held in the extension jar
        messages = ResourceBundle.getBundle(
                        this.getClass().getPackage().getName() + ".resources.Messages", Constant.getLocale());
        }
        
        @SuppressWarnings("deprecation")
        @Override
        public void hook(ExtensionHook extensionHook) {
            super.hook(extensionHook);
            
            if (getView() != null) {
                // Register our top menu item, as long as we're not running as a daemon
                // Use one of the other methods to add to a different menu list
      
                extensionHook.getHookMenu().addToolsMenuItem(getMenuExample());
                
            }

        }
        private JMenuItem getMenuExample() {
            
            menuExample = new JMenuItem();
            menuExample.setName("VulCheck");
            menuExample.setText("VulCheck");

            menuExample.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                    // This is where you do what you want to do.
                    // In this case we'll just show a popup message.  
            		VulnCheckerFrame f = new VulnCheckerFrame();
            		f.setTitle("Vulnerability search");
            		f.setVisible(true);
            		f.setLocationRelativeTo(null);
            		f.setResizable(false);
            }
        });
    
            return menuExample;
        }

}
