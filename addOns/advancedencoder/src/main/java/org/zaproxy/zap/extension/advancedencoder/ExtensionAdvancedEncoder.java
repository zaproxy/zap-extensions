/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.advancedencoder;

import java.awt.Frame;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.ImageIcon;
import javax.swing.text.JTextComponent;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionAdvancedEncoder extends ExtensionAdaptor {

    public static final String SCRIPT_TYPE_ENCODE_DECODE = "encode-decode";
    public static final String NAME = "ExtensionAdvancedEncoder";
    public static final int EXTENSION_ORDER = 87;
    public static final ImageIcon ICON;
    private static final Logger LOGGER = Logger.getLogger(ExtensionAdvancedEncoder.class);
    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionScript.class);
        EXTENSION_DEPENDENCIES = Collections.unmodifiableList(dependencies);
        ICON = createIcon("advancedencoder.png");
    }

    private static ScriptType advEncodeScriptType = null;
    private AdvancedEncodeDecodeDialog encodeDecodeDialog = null;
    private PopupAdvancedEncoderMenu popupEncodeMenu = null;
    private ZapMenuItem toolsMenuEncoder = null;
    private PopupAdvancedEncoderDeleteOutputPanelMenu popupDeleteOutputMenu;

    public ExtensionAdvancedEncoder() {
        super(NAME);
        this.setOrder(EXTENSION_ORDER);
    }

    private static ImageIcon createIcon(String iconName) {
        if (View.isInitialised()) {
            return new ImageIcon(
                    ExtensionAdvancedEncoder.class.getResource(
                            "/org/zaproxy/zap/extension/advancedencoder/resources/" + iconName));
        }
        return null;
    }

    public static ExtensionScript getExtensionScript() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
    }

    public static List<ScriptWrapper> getEncodeDecodeScripts() {
        ExtensionScript extensionScript = getExtensionScript();
        if (extensionScript == null) {
            return new ArrayList<>();
        }

        return extensionScript.getScripts(ExtensionAdvancedEncoder.SCRIPT_TYPE_ENCODE_DECODE);
    }

    private ScriptType getAdvancedEncoderScriptType() {
        if (advEncodeScriptType == null) {
            advEncodeScriptType =
                    new ScriptType(
                            SCRIPT_TYPE_ENCODE_DECODE,
                            "advancedencoder.scripts.type.encodedecode",
                            createIcon("script-advanced-encoder.png"),
                            true);
        }
        return advEncodeScriptType;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (getView() != null) {
            extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuEncode());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuDeleteOutputPanel());
            extensionHook.getHookMenu().addToolsMenuItem(getToolsMenuItemEncoder());
        }

        ExtensionScript extScript = getExtensionScript();
        if (extScript != null) {
            extScript.registerScriptType(getAdvancedEncoderScriptType());
        }
    }

    private ZapMenuItem getToolsMenuItemEncoder() {
        if (toolsMenuEncoder == null) {
            toolsMenuEncoder = new ZapMenuItem("advancedencoder.tools.menu.encdec");
            toolsMenuEncoder.addActionListener(e -> showEncodeDecodeDialog(null));
        }
        return toolsMenuEncoder;
    }

    private PopupAdvancedEncoderMenu getPopupMenuEncode() {
        if (popupEncodeMenu == null) {
            popupEncodeMenu = new PopupAdvancedEncoderMenu();
            popupEncodeMenu.setText(Constant.messages.getString("advancedencoder.popup.title"));
            popupEncodeMenu.addActionListener(
                    e -> showEncodeDecodeDialog(popupEncodeMenu.getLastInvoker()));
        }
        return popupEncodeMenu;
    }

    private PopupAdvancedEncoderDeleteOutputPanelMenu getPopupMenuDeleteOutputPanel() {
        if (popupDeleteOutputMenu == null) {
            popupDeleteOutputMenu = new PopupAdvancedEncoderDeleteOutputPanelMenu();
            popupDeleteOutputMenu.setText(
                    Constant.messages.getString("advancedencoder.popup.delete"));
            popupDeleteOutputMenu.addActionListener(
                    e -> {
                        AdvancedEncodeDecodeDialog advancedEncodeDecodeDialog =
                                showEncodeDecodeDialog(null);
                        advancedEncodeDecodeDialog.deleteOutputPanel(
                                popupDeleteOutputMenu.getLastInvoker());
                    });
        }
        return popupDeleteOutputMenu;
    }

    private AdvancedEncodeDecodeDialog showEncodeDecodeDialog(JTextComponent lastInvoker) {

        List<TabModel> tabModels = new ArrayList<>();
        try {
            tabModels = AdvancedEncoderConfig.loadConfig();
        } catch (ConfigurationException | IOException e) {
            LOGGER.error("Can not load Advanced Encoder Config");
        }

        if (encodeDecodeDialog == null) {
            encodeDecodeDialog = new AdvancedEncodeDecodeDialog(tabModels);
        } else {
            if ((encodeDecodeDialog.getState() & Frame.ICONIFIED) == Frame.ICONIFIED) {
                // bring up to front if iconfied
                encodeDecodeDialog.setState(Frame.NORMAL);
            }
        }

        encodeDecodeDialog.setVisible(true);

        if (lastInvoker != null) {
            encodeDecodeDialog.setInputField(lastInvoker.getSelectedText());
        }
        return encodeDecodeDialog;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();
        ExtensionScript extScript = getExtensionScript();
        if (extScript != null) {
            extScript.removeScriptType(getAdvancedEncoderScriptType());
        }
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("advancedencoder.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("advancedencoder.desc");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return EXTENSION_DEPENDENCIES;
    }
}
