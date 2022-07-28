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
 *     http://www.apache.org/licenses/LICENSE-2.0
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
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import javax.swing.ImageIcon;
import javax.swing.JTree;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.TreeCellRenderer;
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.OverlayIcon;

/**
 * Custom renderer for {@link ScriptsListPanel} to set custom icons and tooltips. If you want
 * tooltips you have to enable them via: <code>
 * ToolTipManager.sharedInstance().registerComponent(tree);</code>
 */
@SuppressWarnings("serial")
public class ScriptsTreeCellRenderer extends DefaultTreeCellRenderer {

    private static final String RESOURCE_ROOT =
            "/org/zaproxy/zap/extension/scripts/resources/icons/";
    private static final String CORE_ROOT = "/resource/icon/16/";

    private static final ImageIcon CROSS_OVERLAY_ICON =
            new ImageIcon(
                    ScriptsTreeCellRenderer.class.getResource(RESOURCE_ROOT + "cross-overlay.png"));
    private static final ImageIcon PENCIL_OVERLAY_ICON =
            new ImageIcon(
                    ScriptsTreeCellRenderer.class.getResource(
                            RESOURCE_ROOT + "pencil-overlay.png"));
    private static final ImageIcon TICK_OVERLAY_ICON =
            new ImageIcon(
                    ScriptsTreeCellRenderer.class.getResource(RESOURCE_ROOT + "tick-overlay.png"));
    private static final ImageIcon WARNING_OVERLAY_ICON =
            new ImageIcon(
                    ScriptsTreeCellRenderer.class.getResource(
                            RESOURCE_ROOT + "exclamation-overlay.png"));
    private static final ImageIcon MISSING_ENGINE_ICON =
            new ImageIcon(
                    ScriptsTreeCellRenderer.class.getResource(
                            RESOURCE_ROOT + "script-missing-engine.png"));

    private static final ImageIcon JAVASCRIPT_ICON =
            new ImageIcon(DisplayUtils.class.getResource(CORE_ROOT + "javascript.png"));
    private static final ImageIcon CSS_ICON =
            new ImageIcon(
                    ScriptsTreeCellRenderer.class.getResource(RESOURCE_ROOT + "document-code.png"));
    private static final ImageIcon WEB_ICON =
            new ImageIcon(
                    ScriptsTreeCellRenderer.class.getResource(
                            RESOURCE_ROOT + "document-globe.png"));

    private ExtensionScriptsUI extension = null;

    private static final long serialVersionUID = -4278691012245035225L;

    private Map<Class<?>, TreeCellRenderer> renderers = new HashMap<>();

    public ScriptsTreeCellRenderer(ExtensionScriptsUI ext) {
        this.extension = ext;
    }

    public void addRenderer(Class<?> c, TreeCellRenderer renderer) {
        this.renderers.put(c, renderer);
    }

    public void removeRenderer(Class<?> c) {
        this.renderers.remove(c);
    }

    /** Sets custom tree node logos. */
    @Override
    public Component getTreeCellRendererComponent(
            JTree tree,
            Object value,
            boolean sel,
            boolean expanded,
            boolean leaf,
            int row,
            boolean hasFocus) {

        super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);

        ScriptNode node = null;
        Object userObject = null;
        if (value instanceof ScriptNode) {
            node = (ScriptNode) value;
            userObject = node.getUserObject();
        }

        if (node != null) {
            for (Entry<Class<?>, TreeCellRenderer> entry : this.renderers.entrySet()) {
                if (entry.getKey().isInstance(node.getUserObject())) {
                    return entry.getValue()
                            .getTreeCellRendererComponent(
                                    tree, value, sel, expanded, leaf, row, hasFocus);
                }
            }

            if (node.isRoot() || node.getParent().isRoot()) {
                // Top 2 levels use same icon .. for now ;)
                setIcon(DisplayUtils.getScaledIcon(ExtensionScriptsUI.ICON));

            } else if (userObject != null && userObject instanceof ScriptWrapper) {
                OverlayIcon icon;
                ScriptWrapper script = (ScriptWrapper) userObject;
                ScriptEngineWrapper engine = script.getEngine();
                if (script.getEngine() == null) {
                    // Scripts loaded from the configs my have loaded before all of the engines
                    try {
                        script.setEngine(
                                extension.getExtScript().getEngineWrapper(script.getEngineName()));
                    } catch (Exception e) {
                        // Failed to find the engine, just keep going
                    }
                }

                if (engine != null) {
                    if (script.getType().hasCapability(ExtensionScriptsUI.CAPABILITY_EXTERNAL)) {
                        String nameLc = script.getName().toLowerCase(Locale.ROOT);
                        if (nameLc.endsWith(".js")) {
                            icon = new OverlayIcon(DisplayUtils.getScaledIcon(JAVASCRIPT_ICON));
                        } else if (nameLc.endsWith(".css")) {
                            icon = new OverlayIcon(DisplayUtils.getScaledIcon(CSS_ICON));
                        } else if (nameLc.endsWith(".html")) {
                            icon = new OverlayIcon(DisplayUtils.getScaledIcon(WEB_ICON));
                        } else {
                            icon =
                                    new OverlayIcon(
                                            DisplayUtils.getScaledIcon(ExtensionScriptsUI.ICON));
                        }
                    } else if (engine.getIcon() != null) {
                        icon = new OverlayIcon(DisplayUtils.getScaledIcon(engine.getIcon()));
                    } else {
                        // Default to the blank script
                        icon = new OverlayIcon(DisplayUtils.getScaledIcon(ExtensionScriptsUI.ICON));
                    }
                    if (script.isChanged() && !node.isTemplate()) {
                        icon.add(DisplayUtils.getScaledIcon(PENCIL_OVERLAY_ICON));
                    }
                    if (script.isError() && !node.isTemplate()) {
                        icon.add(DisplayUtils.getScaledIcon(WARNING_OVERLAY_ICON));
                    }
                    if (script.getType().isEnableable() && !node.isTemplate()) {
                        if (script.isEnabled()) {
                            icon.add(DisplayUtils.getScaledIcon(TICK_OVERLAY_ICON));
                        } else {
                            icon.add(DisplayUtils.getScaledIcon(CROSS_OVERLAY_ICON));
                        }
                    }
                } else {
                    icon = new OverlayIcon(DisplayUtils.getScaledIcon(MISSING_ENGINE_ICON));
                }
                setIcon(icon);

            } else if (node.getType() != null) {
                setIcon(DisplayUtils.getScaledIcon(node.getType().getIcon()));
            }
        }

        return this;
    }

    /*
    @Override
    public boolean isOnHotspot(int arg0, int arg1) {
    	return false;
    }
    */
}
