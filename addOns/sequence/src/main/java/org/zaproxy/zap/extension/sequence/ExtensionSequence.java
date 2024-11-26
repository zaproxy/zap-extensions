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
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.swing.ImageIcon;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.view.View;
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
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionSequence extends ExtensionAdaptor {

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
    private ZapMenuItem activeScanMenu;
    private SequenceAscanDialog ascanDialog;

    private ScriptType scriptType;

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
        getExtScript().removeScriptType(scriptType);
        if (ascanDialog != null) {
            ascanDialog.dispose();
        }
        if (importHarMenuItem != null) {
            importHarMenuItem.unload();
        }
    }

    public ScanPolicy getDefaultScanPolicy() throws ConfigurationException {
        // FIXME: this should be read from the options
        return getExtActiveScan().getPolicyManager().getPolicy("Sequence");
    }

    public Stream<ZestScriptWrapper> getSequences() {
        return extScript.getScripts(ExtensionSequence.TYPE_SEQUENCE).stream()
                .filter(ZestScriptWrapper.class::isInstance)
                .map(ZestScriptWrapper.class::cast);
    }

    public List<String> getSequenceNames() {
        return getSequences().map(ScriptWrapper::getName).collect(Collectors.toList());
    }

    public void activeScanSequences(String policy, List<String> sequences) {
        List<Object> contextSpecificObjects = new ArrayList<>();
        try {
            contextSpecificObjects.add(getExtActiveScan().getPolicyManager().getPolicy(policy));
        } catch (ConfigurationException e4) {
            // Ignore
        }

        for (String seq : sequences) {
            ScriptWrapper script = getExtScript().getScript(seq);
            if (script instanceof ZestScriptWrapper) {
                StdActiveScanRunner zzr =
                        new StdActiveScanRunner(
                                (ZestScriptWrapper) script, null, null, contextSpecificObjects);
                try {
                    zzr.run(null, null);
                } catch (Exception e1) {
                    LOGGER.error(e1.getMessage(), e1);
                }
            }
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
            extensionhook.getHookMenu().addToolsMenuItem(getActiveScanMenu());
            extensionhook.addSessionListener(new SessionChangedListenerImpl());
        }
    }

    /**
     * Gets the script type for sequences.
     *
     * @return the script type.
     */
    public ScriptType getScriptType() {
        return scriptType;
    }

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

    private SequenceAscanDialog getAscanDialog() {
        if (ascanDialog == null) {
            ascanDialog = new SequenceAscanDialog(this, View.getSingleton().getMainFrame());
        }
        return ascanDialog;
    }

    private ZapMenuItem getActiveScanMenu() {
        if (activeScanMenu == null) {
            activeScanMenu = new ZapMenuItem("sequence.tools.menu.ascan");
            activeScanMenu.addActionListener(e -> getAscanDialog().setVisible(true));
        }
        return activeScanMenu;
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
