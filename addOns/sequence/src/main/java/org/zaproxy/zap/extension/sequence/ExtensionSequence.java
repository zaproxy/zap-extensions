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
package org.zaproxy.zap.extension.sequence;

import java.util.ArrayList;
import java.util.List;
import javax.swing.ImageIcon;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.core.scanner.Scanner;
import org.parosproxy.paros.core.scanner.ScannerHook;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.sequence.internal.ImportHarMenuItem;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;

public class ExtensionSequence extends ExtensionAdaptor implements ScannerHook {

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(
                    ExtensionExim.class,
                    ExtensionNetwork.class,
                    ExtensionScript.class,
                    ExtensionZest.class);

    private ExtensionScript extScript;
    private ExtensionActiveScan extActiveScan;
    private static final Logger LOGGER = LogManager.getLogger(ExtensionSequence.class);
    public static final String TYPE_SEQUENCE = "sequence";

    private ImportHarMenuItem importHarMenuItem;

    private List<ScriptWrapper> directScripts = null;
    private SequenceAscanPanel sequencePanel;

    private ScriptType scriptType;

    private boolean scanning = false;

    public ExtensionSequence() {
        super("ExtensionSequence");
        this.setOrder(29);
    }

    @Override
    public void init() {
        super.init();

        scriptType =
                new ScriptType(
                        TYPE_SEQUENCE,
                        "script.type.sequence",
                        hasView()
                                ? new ImageIcon(
                                        getClass()
                                                .getResource("resources/icons/script-sequence.png"))
                                : null,
                        false,
                        new String[] {ScriptType.CAPABILITY_APPEND});
    }

    @Override
    public void initView(ViewDelegate view) {
        super.initView(view);

        ExtensionActiveScan extAscan = getExtActiveScan();
        if (extAscan != null) {
            sequencePanel = new SequenceAscanPanel(getExtScript());
        }
    }

    @Override
    public void postInit() {
        if (sequencePanel != null) {
            getExtActiveScan().addCustomScanPanel(sequencePanel);
        }
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();
        if (sequencePanel != null) {
            getExtActiveScan().removeCustomScanPanel(sequencePanel);
        }
        getExtScript().removeScriptType(scriptType);

        if (importHarMenuItem != null) {
            importHarMenuItem.unload();
        }
    }

    public ScanPolicy getDefaultScanPolicy() throws ConfigurationException {
        // FIXME: this should be read from the options
        return getExtActiveScan().getPolicyManager().getPolicy("Sequence");
    }

    @Override
    public void scannerComplete() {
        if (!scanning && sequencePanel != null) {
            // Active scan all of the selected sequences
            // Need this bool otherwise we will infinitely recurse!
            scanning = true;
            List<ScriptWrapper> scripts = sequencePanel.getPanel(false).getSelectedIncludeScripts();

            List<Object> contextSpecificObjects = new ArrayList<>();
            try {
                contextSpecificObjects.add(getDefaultScanPolicy());
            } catch (ConfigurationException e4) {
                // Ignore
            }
            scripts.forEach(
                    s -> {
                        if (s instanceof ZestScriptWrapper) {
                            StdActiveScanRunner zzr =
                                    new StdActiveScanRunner(
                                            (ZestScriptWrapper) s,
                                            null,
                                            null,
                                            contextSpecificObjects);
                            try {
                                zzr.run(null, null);
                            } catch (Exception e1) {
                                LOGGER.error(e1.getMessage(), e1);
                            }
                        }
                    });
            scanning = false;
        }
    }

    @Override
    public void hook(ExtensionHook extensionhook) {
        super.hook(extensionhook);

        getExtScript().registerScriptType(scriptType);

        if (hasView()) {
            importHarMenuItem =
                    new ImportHarMenuItem(
                            scriptType,
                            getExtension(ExtensionExim.class),
                            getExtension(ExtensionZest.class));
            extensionhook.getHookMenu().addImportMenuItem(importHarMenuItem);
            extensionhook
                    .getHookMenu()
                    .addPopupMenuItem(new SequencePopupMenuItem(this, getExtScript()));
            extensionhook.addSessionListener(new SessionChangedListenerImpl());
        }

        // Add class as a scannerhook (implements the scannerhook interface)
        extensionhook.addScannerHook(this);
    }

    /**
     * Gets the script type for sequences.
     *
     * @return the script type.
     */
    public ScriptType getScriptType() {
        return scriptType;
    }

    @Override
    public void beforeScan(HttpMessage msg, AbstractPlugin plugin, Scanner scanner) {}

    @Override
    public void afterScan(HttpMessage msg, AbstractPlugin plugin, Scanner scanner) {}

    public void setDirectScanScript(ScriptWrapper script) {
        directScripts = new ArrayList<>();
        directScripts.add(script);
    }

    private ExtensionScript getExtScript() {
        if (extScript == null) {
            extScript = getExtension(ExtensionScript.class);
        }
        return extScript;
    }

    private <T extends Extension> T getExtension(Class<T> clazz) {
        return Control.getSingleton().getExtensionLoader().getExtension(clazz);
    }

    protected ExtensionActiveScan getExtActiveScan() {
        if (extActiveScan == null) {
            extActiveScan = getExtension(ExtensionActiveScan.class);
        }
        return extActiveScan;
    }

    private class SessionChangedListenerImpl implements SessionChangedListener {

        @Override
        public void sessionChanged(Session session) {
            // Nothing to do.
        }

        @Override
        public void sessionAboutToChange(Session session) {
            if (importHarMenuItem != null) {
                importHarMenuItem.clear();
            }
        }

        @Override
        public void sessionScopeChanged(Session session) {
            // Nothing to do.

        }

        @Override
        public void sessionModeChanged(Mode mode) {
            // Nothing to do.

        }
    }
}
