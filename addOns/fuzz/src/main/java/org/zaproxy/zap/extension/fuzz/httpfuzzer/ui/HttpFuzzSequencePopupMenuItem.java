/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.httpfuzzer.ui;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.ExtensionPopupMenu;
import org.zaproxy.zap.extension.fuzz.ExtensionFuzz;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerHandler;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerSequenceLauncher;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.script.SequenceScript;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestIndexBasedSequenceRunner;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;

import javax.swing.JMenuItem;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.text.MessageFormat;
import java.util.List;

public class HttpFuzzSequencePopupMenuItem extends ExtensionPopupMenu {

    private static final long serialVersionUID = 1L;
    public static final Logger logger = Logger.getLogger(HttpFuzzSequencePopupMenuItem.class);
    private final ExtensionScript extensionScript;
    private final HttpFuzzerSequenceLauncher httpFuzzerSequenceLauncher;
    private ExtensionZest extensionZest;

    public HttpFuzzSequencePopupMenuItem(ExtensionFuzz extensionFuzz, HttpFuzzerHandler httpFuzzerHandler, ExtensionScript extensionScript, ExtensionZest extensionZest) {
        super();
        this.extensionScript = extensionScript;
        this.extensionZest = extensionZest;
        this.httpFuzzerSequenceLauncher = new HttpFuzzerSequenceLauncher(httpFuzzerHandler, extensionFuzz);
        initialize();
    }

    private void initialize() {
        this.setText(Constant.messages.getString("fuzz.httpfuzzer.popup.menu.fuzz.sequence"));
        this.addMenuListener(new MenuListener() {
            @Override
            public void menuSelected(MenuEvent e) {
                addItems();
            }

            @Override
            public void menuDeselected(MenuEvent e) {

            }

            @Override
            public void menuCanceled(MenuEvent e) {

            }
        });
    }

    @Override
    public int getMenuIndex() {
        return 2;
    }

    private void addItems(){
        SequenceScript selectedScript = getSelectedSequenceScript(0);
        List<HttpMessage> httpMessages = selectedScript.getAllRequestsInScript();
        int messageIndex = 0;
        this.removeAll();
        for (HttpMessage message : httpMessages) {
            addItem(message, messageIndex++);
        }
    }

    private void addItem(HttpMessage message, int messageIndex){
        final int localMessageIndex = messageIndex;
        int messageNumber = messageIndex+1;
        String uri = getUrlDecodedUri(message);
        JMenuItem item = new JMenuItem(messageNumber + ": " + message.getRequestHeader().getMethod() + " " + uri);
        this.add(item);

        item.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                try {
                    startFuzzDialog(localMessageIndex);
                } catch (IOException e1) {
                    String msg = Constant.messages.getString("fuzz.httpfuzzer.popup.menu.fuzz.sequence.script.error.starting");
                    View.getSingleton().showMessageDialog(msg);
                }
            }
        });
    }

    private String getUrlDecodedUri(HttpMessage message){
        String uri = message.getRequestHeader().getURI().toString();
        try {
            return URLDecoder.decode(uri, "UTF8");
        } catch (UnsupportedEncodingException e) {
            return uri;
        }
    }

    private void startFuzzDialog(int localMessageIndex) throws IOException {
        SequenceScript sequenceScript = getSelectedSequenceScript(localMessageIndex);
        if(sequenceScript == null) return;
        httpFuzzerSequenceLauncher.showFuzzerDialogAndRun(sequenceScript, localMessageIndex);
    }

    @Override
    public boolean isEnableForComponent(Component component) {
        return isScriptTree(component) &&
                isNotATemplate() &&
                isSequenceScript() &&
                isScriptWrapperWithEngine();
    }

    private boolean isNotATemplate() {
        ScriptNode node = getSelectedNode();
        return node != null && !node.isTemplate();
    }

    private ScriptNode getSelectedNode() {
        return extensionScript.getScriptUI().getSelectedNode();
    }

    private boolean isSequenceScript() {
        ScriptNode node = getSelectedNode();
        return node != null && node.getType() != null && node.getType().getName().equals(ExtensionFuzz.SCRIPT_TYPE_SEQUENCE);
    }

    private boolean isScriptWrapperWithEngine(){
        ScriptNode node = getSelectedNode();
        return node.getUserObject() != null && node.getUserObject() instanceof ScriptWrapper && ((ScriptWrapper) node.getUserObject()).getEngine() != null;
    }

    private boolean isScriptTree(Component component) {
        return this.extensionScript.getScriptUI() != null
                && component != null
                && this.extensionScript.getScriptUI().getTreeName()
                .equals(component.getName());
    }

    private SequenceScript getSelectedSequenceScript(int indexOfMessage) {
        try {
            ScriptWrapper wrapper = getSelectedScript();
            SequenceScript  sequenceScript = tryGetSequenceScript(indexOfMessage, wrapper);
            if (sequenceScript == null) {
                String msg = Constant.messages.getString("fuzz.httpfuzzer.popup.menu.fuzz.sequence.script.error.interface");
                View.getSingleton().showMessageDialog(MessageFormat.format(msg, wrapper.getName()));
            }
            return sequenceScript;
        } catch (Exception ex) {
            logger.warn("An exception occurred while starting the fuzzer for a sequence script:", ex);
            return null;
        }
    }

    private SequenceScript tryGetSequenceScript(int indexOfMessage, ScriptWrapper wrapper) throws javax.script.ScriptException, IOException {
        if(wrapper instanceof ZestScriptWrapper){
            // Question: Should I inject here a http sender with HttpSender.FUZZER_INITIATOR? Or does not matter?;
            return new ZestIndexBasedSequenceRunner(extensionZest, (ZestScriptWrapper)wrapper, indexOfMessage);
        }

        return extensionScript.getInterface(wrapper, SequenceScript.class);
    }

    private ScriptWrapper getSelectedScript() {
        return (ScriptWrapper) getSelectedNode().getUserObject();
    }
}
