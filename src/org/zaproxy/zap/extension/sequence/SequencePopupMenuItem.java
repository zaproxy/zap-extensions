package org.zaproxy.zap.extension.sequence;

import java.awt.Component;
import java.awt.event.ActionEvent;

import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.script.SequenceScript;

public class SequencePopupMenuItem extends ExtensionPopupMenuItem {

	private static final long serialVersionUID = 1L;
	
	private final ExtensionScript extScript;
	public static final Logger logger = Logger.getLogger(SequencePopupMenuItem.class);
	private ExtensionSequence extension = null;
	

	public SequencePopupMenuItem(ExtensionSequence extension, ExtensionScript extensionScript) {
		super();
		this.extension = extension;
		this.extScript = extensionScript;
		initialize();
	}
	
	private void initialize() {
		this.setText(extension.getMessages().getString("sequence.popupmenuitem.activeScanSequence"));
		
		this.addActionListener(new java.awt.event.ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				try {
					ScriptWrapper wrapper = (ScriptWrapper)extScript.getScriptUI().getSelectedNode().getUserObject();
					SequenceScript scr = extScript.getInterface(wrapper, SequenceScript.class);
					if (scr != null) {
						extension.setDirectScanScript(wrapper);
						scr.scanSequence();
					} else {
						View.getSingleton().showMessageDialog(
								extension.getMessages().getString("sequence.popupmenuitem.script.error.interface"));
					}
				} catch(Exception ex) {
					logger.warn("An exception occurred while starting an active scan for a sequence script:", ex);	
				}
			}
		});
	}

	@Override
	public boolean isEnableForComponent(Component invoker) {
		if(isScriptTree(invoker)) {
			ScriptNode node = extScript.getScriptUI().getSelectedNode();
			if(node != null) {
				if(node.isTemplate()) {
					return false;
				}
				ScriptType type = node.getType();
				if(type != null) {
					if(type.getName().equals(ExtensionSequence.TYPE_SEQUENCE)) {
						Object obj = node.getUserObject();
						if(obj != null) {						
							if(obj instanceof ScriptWrapper) {
								return ((ScriptWrapper) obj).getEngine() != null;
							}
						}
					}
				}
			}
		}
		return false;
	}
	
	public boolean isScriptTree(Component component) {
		return this.extScript.getScriptUI() != null
		&& component != null
		&& this.extScript.getScriptUI().getTreeName()
		.equals(component.getName());
		}
	}
