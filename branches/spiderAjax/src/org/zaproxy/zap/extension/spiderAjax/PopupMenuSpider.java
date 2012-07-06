package org.zaproxy.zap.extension.spiderAjax;

import java.awt.Component;
import java.util.ResourceBundle;
import javax.swing.ImageIcon;
import javax.swing.JTree;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.model.SiteNode;

public class PopupMenuSpider extends ExtensionPopupMenuItem {

	private static final long serialVersionUID = 1L;
	private ExtensionAjax extension = null;
	private JTree treeSite = null;

	/** 
     * 
     */
	public PopupMenuSpider(ExtensionAjax extension) {
		super();
		this.extension=extension;
		initialize();
	}

	/**
	 * @param label
	 */
	public PopupMenuSpider(String label,ExtensionAjax extension) {
		super(label);
		this.extension=extension;

	}

	@Override
	public boolean isSubMenu() {
		return true;
	}

	@Override
	public String getParentMenuName() {
		return Constant.messages.getString("attack.site.popup");
	}

	@Override
	public int getParentMenuIndex() {
		return ATTACK_MENU_INDEX;
	}

	/**
	 * This method initializes this
	 * 
	 * @return void
	 */
	private void initialize() {
		 this.setText(Constant.messages.getString("ajax.site.popup"));
	        this.setIcon(new ImageIcon(getClass().getClassLoader().getResource("org/zaproxy/zap/extension/spiderAjax/16.png")));

	        this.addActionListener(new java.awt.event.ActionListener() { 

	        	@Override
	        	public void actionPerformed(java.awt.event.ActionEvent e) {    
	        		if (treeSite != null) {
	        		    SiteNode node = (SiteNode) treeSite.getLastSelectedPathComponent();
	        		    if (node != null) {
	        		    	extension.spiderSite(node, true);
	        		    }
	        		}

	        	}
	        });

	}
	@Override
	public boolean isEnableForComponent(Component invoker) {
		
		treeSite = getTree(invoker);
		if (treeSite != null) {
			SiteNode node = (SiteNode) treeSite.getLastSelectedPathComponent();
			if (node != null && !node.isRoot() && !extension.isScanning(node, true)) {
				this.setEnabled(true);
			} else {
				this.setEnabled(false);
			}
			return true;
		}
		return false;
	}

	private JTree getTree(Component invoker) {
		if (invoker instanceof JTree) {
			JTree tree = (JTree) invoker;
			if (tree.getName().equals("treeSite")) {
				return tree;
			}
		}

		return null;
	}

	void setExtension(ExtensionAjax extension) {
		this.extension = extension;
	}

}

