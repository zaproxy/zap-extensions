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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.swing.ImageIcon;
import org.apache.log4j.Logger;
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

    private static final Logger LOGGER = Logger.getLogger(ExtensionJython.class);

    private static final List<Class<? extends Extension>> EXTENSION_DEPENDENCIES;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionScript.class);
        EXTENSION_DEPENDENCIES = Collections.unmodifiableList(dependencies);

        PYTHON_ICON =
                View.isInitialised()
                        ? new ImageIcon(
                                ExtensionJython.class.getResource(
                                        "/org/zaproxy/zap/extension/jython/resources/python.png"))
                        : null;
    }

    private ExtensionScript extScript = null;
    private JythonOptionsParam jythonOptionsParam;
    private CountDownLatch engineLoaderCDL;

    public ExtensionJython() {
        super(NAME);
        this.setOrder(74);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        this.jythonOptionsParam = new JythonOptionsParam();

        ScriptEngineManager mgr = new ScriptEngineManager();

        ScriptEngine se = mgr.getEngineByExtension("py");

        if (se == null) {
            if (getView() == null) {
                engineLoaderCDL = new CountDownLatch(1);
            }

            Thread engineLoaderThread =
                    new Thread(
                            new Runnable() {

                                @Override
                                public void run() {
                                    try {
                                        LOGGER.info("Loading Jython engine...");
                                        getExtScript()
                                                .registerScriptEngineWrapper(
                                                        new JythonEngineWrapper(
                                                                jythonOptionsParam,
                                                                new PyScriptEngineFactory()
                                                                        .getScriptEngine()));
                                        LOGGER.info("Jython engine loaded.");
                                    } finally {
                                        if (engineLoaderCDL != null) {
                                            engineLoaderCDL.countDown();
                                        }
                                    }
                                }
                            });
            engineLoaderThread.setName("ZAP-Jython-EngineLoader");
            engineLoaderThread.start();
        }

        extensionHook.addOptionsParamSet(this.jythonOptionsParam);
        if (null != super.getView()) {
            extensionHook.getHookView().addOptionPanel(new JythonOptionsPanel());
        }
    }

    @Override
    public void postInit() {
        super.postInit();

        if (engineLoaderCDL != null) {
            try {
                LOGGER.info("Waiting for Jython engine to load...");
                engineLoaderCDL.await();
            } catch (InterruptedException e) {
                LOGGER.warn("Interrupted while waiting for the Jython engine to load.");
                Thread.currentThread().interrupt();
            } finally {
                engineLoaderCDL = null;
            }
        }
    }

    @Override
    public boolean canUnload() {
        return false;
    }

    private ExtensionScript getExtScript() {
        if (extScript == null) {
            extScript =
                    (ExtensionScript)
                            Control.getSingleton()
                                    .getExtensionLoader()
                                    .getExtension(ExtensionScript.NAME);
        }
        return extScript;
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("jython.desc");
    }

    @Override
    public URL getURL() {
        try {
            return new URL(Constant.ZAP_HOMEPAGE);
        } catch (MalformedURLException e) {
            return null;
        }
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return EXTENSION_DEPENDENCIES;
    }
}
