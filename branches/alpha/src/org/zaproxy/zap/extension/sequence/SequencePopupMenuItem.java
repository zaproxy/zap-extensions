package org.zaproxy.zap.extension.sequence;

import java.awt.Component;
import java.awt.event.ActionEvent;

import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.script.SequenceScript;

public class SequencePopupMenuItem extends ExtensionPopupMenuItem {

	private static final long serialVersionUID = 1L;
	
	private ExtensionScript extScript = null;
	public static final Logger logger = Logger.getLogger(SequencePopupMenuItem.class);
	private ExtensionSequence extension = null;
	

	public SequencePopupMenuItem(ExtensionSequence extension) {
		super();
		this.extension = extension;
		initialize();
	}
	
	private void initialize() {
		// TODO: Add i18n key for this string.
		this.setText("Active scan sequence");
		
		this.addActionListener(new java.awt.event.ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				try {
					ScriptWrapper wrapper = (ScriptWrapper)getExtScript().getScriptUI().getSelectedNode().getUserObject();
					SequenceScript scr = getExtScript().getInterface(wrapper, SequenceScript.class);
					extension.setDirectScanScript(wrapper);
					scr.scanSequence();
				} catch(Exception ex) {
					logger.info("An exception occurred while starting an active scan for a sequence script: " + ex.getMessage(), ex);	
				}
			}
		});
	}
	
	
	private ExtensionScript getExtScript() {
		if(extScript == null) {
			extScript = (ExtensionScript) Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
		}
		return extScript;
	}

	@Override
	public boolean isEnableForComponent(Component invoker) {
		if(isScriptTree(invoker)) {
			ScriptNode node = this.getExtScript().getScriptUI().getSelectedNode();
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
		return this.getExtScript().getScriptUI() != null
		&& component != null
		&& this.getExtScript().getScriptUI().getTreeName()
		.equals(component.getName());
		}
	}
