/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2013 The ZAP Development Team
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.scripts;

import java.awt.Component;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.swing.ImageIcon;
import javax.swing.JTree;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.TreeCellRenderer;

import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.view.OverlayIcon;

/**
 * Custom renderer for {@link ScriptsListPanel} to set custom icons
 * and tooltips. If you want tooltips you have to enable them via:
 * <code>ToolTipManager.sharedInstance().registerComponent(tree);</code>
 */
public class ScriptsTreeCellRenderer extends DefaultTreeCellRenderer {
	
	private static final String RESOURCE_ROOT = "/org/zaproxy/zap/extension/scripts/resource/icons/";
	
	private static final ImageIcon CROSS_OVERLAY_ICON = 
			new ImageIcon(ScriptsTreeCellRenderer.class.getResource(RESOURCE_ROOT + "cross-overlay.png"));
	private static final ImageIcon PENCIL_OVERLAY_ICON = 
			new ImageIcon(ScriptsTreeCellRenderer.class.getResource(RESOURCE_ROOT + "pencil-overlay.png"));
	private static final ImageIcon TICK_OVERLAY_ICON = 
			new ImageIcon(ScriptsTreeCellRenderer.class.getResource(RESOURCE_ROOT + "tick-overlay.png"));
	private static final ImageIcon WARNING_OVERLAY_ICON = 
			new ImageIcon(ScriptsTreeCellRenderer.class.getResource(RESOURCE_ROOT + "exclamation-overlay.png"));

	private ExtensionScripts extension = null;
	
	private static final long serialVersionUID = -4278691012245035225L;
	
	@SuppressWarnings("rawtypes")
	private Map<Class, TreeCellRenderer> renderers = new HashMap<Class, TreeCellRenderer>();

	public ScriptsTreeCellRenderer(ExtensionScripts ext) {
		this.extension = ext;
	}
	
	@SuppressWarnings("rawtypes")
	public void addRenderer(Class c, TreeCellRenderer renderer) {
		this.renderers.put(c, renderer);
	}

	/**
	 * Sets custom tree node logos.
	 */
	@SuppressWarnings("rawtypes")
	@Override
	public Component getTreeCellRendererComponent(JTree tree, Object value,
			boolean sel, boolean expanded, boolean leaf, int row,
			boolean hasFocus) {

		super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);
		
		ScriptNode node = null;
		Object userObject = null;
		if (value instanceof ScriptNode) {
			node = (ScriptNode) value;
			userObject = node.getUserObject();
		}
		
		if (node != null) {
			for (Entry<Class, TreeCellRenderer> entry : this.renderers.entrySet()) {
				if (entry.getKey().isInstance(node.getUserObject())) {
					return entry.getValue().getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);
				}
			}
			
			
			if (node.isRoot() || node.getParent().isRoot()) {
				// Top 2 levels use same icon .. for now ;)
				setIcon(ExtensionScripts.ICON);
				
			} else if (userObject != null && userObject instanceof ScriptWrapper) {
				OverlayIcon icon;
				ScriptWrapper script = (ScriptWrapper) userObject;
				ScriptEngineWrapper engine = script.getEngine();
				if (script.getEngine() == null) {
					// Scripts loaded from the configs my have loaded before all of the engines
					try {
						script.setEngine(extension.getExtScript().getEngineWrapper(script.getEngineName()));
					} catch (Exception e) {
						// Failed to find the engine, just keep going
					}
				}
				
				if (engine != null && engine.getIcon() != null) {
					icon = new OverlayIcon(engine.getIcon());
				} else {
					// Default to the blank script
					icon = new OverlayIcon(ExtensionScripts.ICON);
				}
				if (script.isChanged() && ! node.isTemplate()) {
					icon.add(PENCIL_OVERLAY_ICON);
				}
				if (script.isError() && ! node.isTemplate()) {
					icon.add(WARNING_OVERLAY_ICON);
				}
				if (script.getType().isEnableable() && ! node.isTemplate()) {
					if (script.isEnabled()) {
						icon.add(TICK_OVERLAY_ICON);
					} else {
						icon.add(CROSS_OVERLAY_ICON);
					}
				}
				setIcon(icon);
				
			} else if (node.getType() != null) {
				setIcon(node.getType().getIcon());
			}
		}

		return this;
	}
}
