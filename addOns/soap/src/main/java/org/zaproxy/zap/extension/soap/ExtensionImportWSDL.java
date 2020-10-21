/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.soap;

import java.awt.event.KeyEvent;
import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import javax.swing.JFileChooser;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionImportWSDL extends ExtensionAdaptor {

    public static final String NAME = "ExtensionImportWSDL";

    private static final Logger LOG = Logger.getLogger(ExtensionImportWSDL.class);
    private static final String THREAD_PREFIX = "ZAP-Import-WSDL-";

    private ZapMenuItem menuImportLocalWSDL = null;
    private ZapMenuItem menuImportUrlWSDL = null;
    private int threadId = 1;

    private WSDLCustomParser parser = new WSDLCustomParser();
    private WSDLSpider spiderParser;

    public ExtensionImportWSDL() {
        super(NAME);
        this.setOrder(158);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addApiImplementor(new SoapAPI(this));

        if (getView() != null) {
            extensionHook.getHookMenu().addImportMenuItem(getMenuImportLocalWSDL());
            extensionHook.getHookMenu().addImportMenuItem(getMenuImportUrlWSDL());

            /*
             * Custom spider parser is added in order to explore not only WSDL files, but
             * also their WSDL endpoints.
             */
            ExtensionSpider spider =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionSpider.class);
            if (spider != null) {
                spiderParser = new WSDLSpider();
                spider.addCustomParser(spiderParser);
            }
        }
    }

    @Override
    public void postInit() {
        super.postInit();
        try {
            addScript();
        } catch (IOException e) {
            LOG.warn("Could not add SOAP Support script.");
        }
    }

    @Override
    public void unload() {
        super.unload();
        /* Destroys current ImportWSDL singleton instance. */
        ImportWSDL.destroy();

        if (spiderParser != null) {
            Control.getSingleton()
                    .getExtensionLoader()
                    .getExtension(ExtensionSpider.class)
                    .removeCustomParser(spiderParser);
        }
    }

    /* Menu option to import a local WSDL file. */
    private ZapMenuItem getMenuImportLocalWSDL() {
        if (menuImportLocalWSDL == null) {
            menuImportLocalWSDL =
                    new ZapMenuItem(
                            "soap.topmenu.import.importWSDL",
                            getView()
                                    .getMenuShortcutKeyStroke(
                                            KeyEvent.VK_I, KeyEvent.SHIFT_DOWN_MASK, false));
            menuImportLocalWSDL.setToolTipText(
                    Constant.messages.getString("soap.topmenu.import.importWSDL.tooltip"));

            menuImportLocalWSDL.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            // Prompt for a WSDL file.
                            final JFileChooser chooser =
                                    new JFileChooser(
                                            Model.getSingleton()
                                                    .getOptionsParam()
                                                    .getUserDirectory());
                            FileNameExtensionFilter filter =
                                    new FileNameExtensionFilter(
                                            Constant.messages.getString(
                                                    "soap.topmenu.import.importWSDL.filter.description"),
                                            "wsdl");
                            chooser.setFileFilter(filter);
                            int rc = chooser.showOpenDialog(View.getSingleton().getMainFrame());
                            if (rc == JFileChooser.APPROVE_OPTION) {
                                fileUrlWSDLImport(chooser.getSelectedFile());
                            }
                        }
                    });
        }
        return menuImportLocalWSDL;
    }

    /* Menu option to import a WSDL file from a given URL. */
    private ZapMenuItem getMenuImportUrlWSDL() {
        if (menuImportUrlWSDL == null) {
            menuImportUrlWSDL =
                    new ZapMenuItem(
                            "soap.topmenu.import.importRemoteWSDL",
                            getView().getMenuShortcutKeyStroke(KeyEvent.VK_J, 0, false));
            menuImportUrlWSDL.setToolTipText(
                    Constant.messages.getString("soap.topmenu.import.importRemoteWSDL.tooltip"));

            final ExtensionImportWSDL shadowCopy = this;
            menuImportUrlWSDL.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            SwingUtilities.invokeLater(
                                    new Runnable() {
                                        @Override
                                        public void run() {
                                            new ImportFromUrlDialog(
                                                    View.getSingleton().getMainFrame(), shadowCopy);
                                        }
                                    });
                        }
                    });
        }
        return menuImportUrlWSDL;
    }

    /* Called from external classes in a threaded mode. */
    public void extUrlWSDLImport(final String url) {
        parser.extUrlWSDLImport(url, THREAD_PREFIX + threadId++);
    }

    public void fileUrlWSDLImport(final File file) {
        parser.extFileWSDLImport(file, THREAD_PREFIX + threadId++);
    }

    private void addScript() throws IOException {
        ExtensionScript extScript =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        String scriptName = "SOAP Support.js";
        if (extScript != null && extScript.getScript(scriptName) == null) {
            ScriptType variantType =
                    extScript.getScriptType(ExtensionActiveScan.SCRIPT_TYPE_VARIANT);
            ScriptEngineWrapper engine = extScript.getEngineWrapper("Oracle Nashorn");
            if (variantType != null && engine != null) {
                File scriptPath =
                        Paths.get(
                                        Constant.getZapHome(),
                                        ExtensionScript.SCRIPTS_DIR,
                                        ExtensionScript.SCRIPTS_DIR,
                                        ExtensionActiveScan.SCRIPT_TYPE_VARIANT,
                                        scriptName)
                                .toFile();
                ScriptWrapper script =
                        new ScriptWrapper(
                                scriptName,
                                Constant.messages.getString("soap.script.description"),
                                engine,
                                variantType,
                                true,
                                scriptPath);
                script.setLoadOnStart(true);
                script.reloadScript();
                extScript.addScript(script, false);
            }
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("soap.desc");
    }
}
