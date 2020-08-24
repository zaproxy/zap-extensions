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

import java.net.HttpCookie;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import javax.swing.ImageIcon;
import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.core.scanner.Scanner;
import org.parosproxy.paros.core.scanner.ScannerHook;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptCollection;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.script.SequenceScript;

public class ExtensionSequence extends ExtensionAdaptor implements ScannerHook {

    private static final List<Class<? extends Extension>> DEPENDENCIES;

    private ExtensionScript extScript;
    private ExtensionActiveScan extActiveScan;
    public static final Logger logger = Logger.getLogger(ExtensionSequence.class);
    public static final ImageIcon ICON =
            new ImageIcon(
                    ExtensionSequence.class.getResource(
                            "/org/zaproxy/zap/extension/sequence/resources/icons/script-sequence.png"));
    public static final String TYPE_SEQUENCE = "sequence";

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionScript.class);
        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    private List<ScriptWrapper> directScripts = null;
    private SequenceAscanPanel sequencePanel;

    private ScriptType scriptType;

    public ExtensionSequence() {
        super("ExtensionSequence");
        this.setOrder(29);
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
    }

    @Override
    public void scannerComplete() {
        // Reset the sequence extension
        this.directScripts = null;
    }

    @Override
    public void hook(ExtensionHook extensionhook) {
        super.hook(extensionhook);

        // Create a new sequence script type and register
        scriptType =
                new ScriptType(
                        TYPE_SEQUENCE,
                        "script.type.sequence",
                        ICON,
                        false,
                        new String[] {"append"});
        getExtScript().registerScriptType(scriptType);

        if (getView() != null) {
            extensionhook
                    .getHookMenu()
                    .addPopupMenuItem(new SequencePopupMenuItem(this, getExtScript()));
        }

        // Add class as a scannerhook (implements the scannerhook interface)
        extensionhook.addScannerHook(this);
    }

    @Override
    public void beforeScan(HttpMessage msg, AbstractPlugin plugin, Scanner scanner) {
        // If the HttpMessage has a HistoryReference with an ID that is also in the HashMap of the
        // Scanner,
        // then the message has a specific Sequence script to scan.
        SequenceScript seqScr = getIncludedSequenceScript(msg, scanner);

        // If any script was found, send all the requests prior to the message to be scanned.
        if (seqScr != null) {
            HttpMessage newMsg = seqScr.runSequenceBefore(msg, plugin);
            updateMessage(msg, newMsg);
        }
    }

    @Override
    public void afterScan(HttpMessage msg, AbstractPlugin plugin, Scanner scanner) {
        // If the HttpMessage has a HistoryReference with an ID that is also in the HashMap of the
        // Scanner,
        // then the message has a specific Sequence script to scan.
        SequenceScript seqScr = getIncludedSequenceScript(msg, scanner);

        // If any script was found, send all the requests after the message that was scanned.
        if (seqScr != null) {
            seqScr.runSequenceAfter(msg, plugin);
        }
    }

    private SequenceScript getIncludedSequenceScript(HttpMessage msg, Scanner scanner) {
        List<ScriptWrapper> sequences = directScripts;
        if (sequences == null) {
            Set<ScriptCollection> scs = scanner.getScriptCollections();
            if (scs != null) {
                for (ScriptCollection sc : scs) {
                    if (sc.getType().getName().equals(TYPE_SEQUENCE)) {
                        sequences = sc.getScripts();
                        break;
                    }
                }
            }
        }
        if (sequences != null) {
            for (ScriptWrapper wrapper : sequences) {
                try {
                    SequenceScript seqScr =
                            getExtScript().getInterface(wrapper, SequenceScript.class);
                    if (seqScr != null) {
                        if (seqScr.isPartOfSequence(msg)) {
                            return seqScr;
                        }
                    }
                } catch (Exception e) {
                    logger.debug(
                            "Exception occurred, while trying to fetch Included Sequence Script: "
                                    + e.getMessage());
                }
            }
        }
        return null;
    }

    public void setDirectScanScript(ScriptWrapper script) {
        directScripts = new ArrayList<>();
        directScripts.add(script);
    }

    private void updateMessage(HttpMessage msg, HttpMessage newMsg) {
        msg.setRequestHeader(newMsg.getRequestHeader());
        msg.setRequestBody(newMsg.getRequestBody());
        msg.setCookies(new ArrayList<HttpCookie>());
    }

    private ExtensionScript getExtScript() {
        if (extScript == null) {
            extScript =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        }
        return extScript;
    }

    private ExtensionActiveScan getExtActiveScan() {
        if (extActiveScan == null) {
            extActiveScan =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionActiveScan.class);
        }
        return extActiveScan;
    }
}
