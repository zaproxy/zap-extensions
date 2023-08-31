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
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.Database;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.DatabaseUnsupportedException;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.model.ValueGenerator;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionImportWSDL extends ExtensionAdaptor {

    public static final String NAME = "ExtensionImportWSDL";
    public static final String STATS_ADDED_URLS = "soap.urls.added";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionCommonlib.class);

    private static final Logger LOGGER = LogManager.getLogger(ExtensionImportWSDL.class);
    private static final String THREAD_PREFIX = "ZAP-Import-WSDL-";

    private ZapMenuItem menuImportWsdl;
    private ImportDialog importDialog;
    private int threadId = 1;

    private final TableWsdl table = new TableWsdl();
    private final WSDLCustomParser parser = new WSDLCustomParser(this::getValueGenerator, table);

    public ExtensionImportWSDL() {
        super(NAME);
        this.setOrder(158);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    private ValueGenerator getValueGenerator() {
        return Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionCommonlib.class)
                .getValueGenerator();
    }

    public WSDLCustomParser getParser() {
        return parser;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addApiImplementor(new SoapAPI(this));
        extensionHook.addVariant(VariantSoap.class);

        if (hasView()) {
            extensionHook.getHookMenu().addImportMenuItem(getMenuImportWsdl());
            extensionHook.addSessionListener(
                    new SessionChangedListener() {
                        @Override
                        public void sessionAboutToChange(Session session) {
                            if (importDialog != null) {
                                importDialog.clearFields();
                            }
                        }

                        @Override
                        public void sessionChanged(Session session) {}

                        @Override
                        public void sessionScopeChanged(Session session) {}

                        @Override
                        public void sessionModeChanged(Control.Mode mode) {}
                    });
        }
    }

    @Override
    public void postInit() {
        ExtensionScript extScript =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        String scriptName = "SOAP Support.js";
        if (extScript != null && extScript.getScript(scriptName) != null) {
            extScript.removeScript(extScript.getScript(scriptName));
        }
    }

    @Override
    public void unload() {
        super.unload();
        if (importDialog != null) {
            importDialog.dispose();
        }
    }

    @Override
    public void databaseOpen(Database db) throws DatabaseException, DatabaseUnsupportedException {
        db.addDatabaseListener(table);
        table.databaseOpen(db.getDatabaseServer());
    }

    protected TableWsdl getTable() {
        return table;
    }

    private ZapMenuItem getMenuImportWsdl() {
        if (menuImportWsdl == null) {
            menuImportWsdl =
                    new ZapMenuItem(
                            "soap.topmenu.import.importWSDL",
                            getView().getMenuShortcutKeyStroke(KeyEvent.VK_J, 0, false));
            menuImportWsdl.setToolTipText(
                    Constant.messages.getString("soap.topmenu.import.importWSDL.tooltip"));
            menuImportWsdl.addActionListener(
                    e -> {
                        if (importDialog == null) {
                            importDialog = new ImportDialog(getView().getMainFrame(), this);
                        }
                        importDialog.setVisible(true);
                    });
        }
        return menuImportWsdl;
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
