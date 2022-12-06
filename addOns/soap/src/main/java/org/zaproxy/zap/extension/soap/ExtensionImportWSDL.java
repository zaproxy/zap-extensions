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
import java.security.InvalidParameterException;
import javax.swing.JFileChooser;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.Database;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.DatabaseUnsupportedException;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.model.DefaultValueGenerator;
import org.zaproxy.zap.model.ValueGenerator;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionImportWSDL extends ExtensionAdaptor {

    public static final String NAME = "ExtensionImportWSDL";
    public static final String STATS_ADDED_URLS = "soap.urls.added";

    private static final Logger LOG = LogManager.getLogger(ExtensionImportWSDL.class);
    private static final String THREAD_PREFIX = "ZAP-Import-WSDL-";
    private static final String SCRIPT_NAME = "SOAP Support.js";

    private ZapMenuItem menuImportLocalWSDL = null;
    private ZapMenuItem menuImportUrlWSDL = null;
    private int threadId = 1;

    private final TableWsdl table = new TableWsdl();
    private final WSDLCustomParser parser = new WSDLCustomParser(this::getValueGenerator, table);
    private ValueGenerator valueGenerator;

    public ExtensionImportWSDL() {
        super(NAME);
        this.setOrder(158);

        setValueGenerator(null);
    }

    public void setValueGenerator(ValueGenerator valueGenerator) {
        this.valueGenerator = valueGenerator == null ? new DefaultValueGenerator() : valueGenerator;
    }

    private ValueGenerator getValueGenerator() {
        return valueGenerator;
    }

    public WSDLCustomParser getParser() {
        return parser;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addApiImplementor(new SoapAPI(this));

        if (hasView()) {
            extensionHook.getHookMenu().addImportMenuItem(getMenuImportLocalWSDL());
            extensionHook.getHookMenu().addImportMenuItem(getMenuImportUrlWSDL());
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
        removeScript();
    }

    @Override
    public void databaseOpen(Database db) throws DatabaseException, DatabaseUnsupportedException {
        db.addDatabaseListener(table);
        table.databaseOpen(db.getDatabaseServer());
    }

    protected TableWsdl getTable() {
        return table;
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
                    e -> {
                        // Prompt for a WSDL file.
                        final JFileChooser chooser =
                                new JFileChooser(
                                        Model.getSingleton().getOptionsParam().getUserDirectory());
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
                    e ->
                            SwingUtilities.invokeLater(
                                    () ->
                                            new ImportFromUrlDialog(
                                                    View.getSingleton().getMainFrame(),
                                                    shadowCopy)));
        }
        return menuImportUrlWSDL;
    }

    public void syncImportWsdlUrl(final String url) {
        parser.syncImportWsdlUrl(url);
    }

    public void syncImportWsdlFile(final File file) {
        parser.syncImportWsdlFile(file);
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
        if (extScript != null && extScript.getScript(SCRIPT_NAME) == null) {
            ScriptType variantType =
                    extScript.getScriptType(ExtensionActiveScan.SCRIPT_TYPE_VARIANT);
            ScriptEngineWrapper engine = getEngine(extScript, "Oracle Nashorn");
            if (variantType != null && engine != null) {
                File scriptPath =
                        Paths.get(
                                        Constant.getZapHome(),
                                        ExtensionScript.SCRIPTS_DIR,
                                        ExtensionScript.SCRIPTS_DIR,
                                        ExtensionActiveScan.SCRIPT_TYPE_VARIANT,
                                        SCRIPT_NAME)
                                .toFile();
                ScriptWrapper script =
                        new ScriptWrapper(
                                SCRIPT_NAME,
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

    private void removeScript() {
        ExtensionScript extScript =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        if (extScript != null && extScript.getScript(SCRIPT_NAME) != null) {
            extScript.removeScript(extScript.getScript(SCRIPT_NAME));
        }
    }

    private static ScriptEngineWrapper getEngine(ExtensionScript ext, String engineName) {
        try {
            return ext.getEngineWrapper(engineName);
        } catch (InvalidParameterException e) {
            LOG.warn("The {} engine was not found, script variant will not be added.", engineName);
        }
        return null;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public boolean supportsDb(String type) {
        return Database.DB_TYPE_HSQLDB.equals(type);
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("soap.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("soap.desc");
    }
}
