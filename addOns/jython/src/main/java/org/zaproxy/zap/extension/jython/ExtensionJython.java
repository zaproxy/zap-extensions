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
package org.zaproxy.zap.extension.jython;

import java.util.List;
import javax.swing.ImageIcon;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.python.jsr223.PyScriptEngineFactory;
import org.zaproxy.zap.extension.script.ExtensionScript;

public class ExtensionJython extends ExtensionAdaptor {

    public static final String NAME = "ExtensionJython";
    public static final ImageIcon PYTHON_ICON;

    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES =
            List.of(ExtensionScript.class);

    static {
        PYTHON_ICON =
                View.isInitialised()
                        ? new ImageIcon(
                                ExtensionJython.class.getResource(
                                        "/org/zaproxy/zap/extension/jython/resources/python.png"))
                        : null;
    }

    private ExtensionScript extScript = null;
    private JythonOptionsParam jythonOptionsParam;
    private JythonOptionsPanel jythonOptionsPanel;
    private JythonEngineWrapper engineWrapper;

    public ExtensionJython() {
        super(NAME);
        this.setOrder(74);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        this.jythonOptionsParam = new JythonOptionsParam();

        engineWrapper = new JythonEngineWrapper(jythonOptionsParam, new PyScriptEngineFactory());
        getExtScript().registerScriptEngineWrapper(engineWrapper);

        extensionHook.addOptionsParamSet(this.jythonOptionsParam);
        if (hasView()) {
            String[] scriptEngineNode = {
                Constant.messages.getString("options.script.title"),
                Constant.messages.getString("scripts.options.engine.title")
            };
            getView().getOptionsDialog().addParamPanel(scriptEngineNode, getOptionsPanel(), true);
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (hasView()) {
            getView().getOptionsDialog().removeParamPanel(getOptionsPanel());
        }

        getExtScript().removeScriptEngineWrapper(engineWrapper);
    }

    private ExtensionScript getExtScript() {
        if (extScript == null) {
            extScript =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        }
        return extScript;
    }

    private JythonOptionsPanel getOptionsPanel() {
        if (jythonOptionsPanel == null) {
            jythonOptionsPanel = new JythonOptionsPanel();
        }
        return jythonOptionsPanel;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("jython.desc");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return EXTENSION_DEPENDENCIES;
    }
}
