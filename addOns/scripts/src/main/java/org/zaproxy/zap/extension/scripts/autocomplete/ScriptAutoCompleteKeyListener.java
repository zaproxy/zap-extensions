/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.scripts.autocomplete;

import java.awt.Point;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.Map;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType;
import org.zaproxy.zap.control.ExtensionFactory;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.scripts.ExtensionScriptsUI;

public class ScriptAutoCompleteKeyListener extends KeyAdapter {

    private Map<String, Map<String, String>> typeToClassMaps = new HashMap<>();

    private JTextArea textInput;
    private ScriptAutoCompleteMenu textPopupMenu;
    private Class<?> lastReturnType;
    private String scriptType;
    private boolean enabled = true;

    private static final Logger LOG = LogManager.getLogger(ScriptAutoCompleteKeyListener.class);

    public ScriptAutoCompleteKeyListener(JTextArea textInput) {
        this.textInput = textInput;

        // Active Rules
        HashMap<String, String> activeRuleMap = new HashMap<>();
        activeRuleMap.put("as", "org.zaproxy.zap.extension.ascan.ScriptsActiveScanner");
        activeRuleMap.put("msg", "org.parosproxy.paros.network.HttpMessage");
        activeRuleMap.put("param", "java.lang.String");
        activeRuleMap.put("value", "java.lang.String");
        typeToClassMaps.put(ExtensionActiveScan.SCRIPT_TYPE_ACTIVE, activeRuleMap);

        // Authentication
        HashMap<String, String> authMap = new HashMap<>();
        authMap.put("helper", "org.zaproxy.zap.authentication.AuthenticationHelper");
        authMap.put("paramsValues", "java.util.Map");
        authMap.put(
                "credentials", "org.zaproxy.zap.authentication.GenericAuthenticationCredentials");
        typeToClassMaps.put(ScriptBasedAuthenticationMethodType.SCRIPT_TYPE_AUTH, authMap);

        // Extender
        HashMap<String, String> extendMap = new HashMap<>();
        extendMap.put("helper", "org.zaproxy.zap.extension.scripts.ExtenderScriptHelper");
        typeToClassMaps.put(ExtensionScriptsUI.SCRIPT_EXT_TYPE, extendMap);

        // Fuzzer HTTP Processor
        HashMap<String, String> fuzzHttpMap = new HashMap<>();
        fuzzHttpMap.put(
                "utils", "org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerTaskProcessorUtils");
        fuzzHttpMap.put("message", "org.parosproxy.paros.network.HttpMessage");
        fuzzHttpMap.put("fuzzResult", "org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzResult");
        // Defined in org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.HttpFuzzerProcessorScript
        // not using directly as its in another add-on
        typeToClassMaps.put("httpfuzzerprocessor", fuzzHttpMap);

        // Fuzzer Websocket Processor
        HashMap<String, String> fuzzWsMap = new HashMap<>();
        fuzzWsMap.put(
                "utils",
                "org.zaproxy.zap.extension.websocket.fuzz.WebSocketFuzzerTaskProcessorUtils");
        fuzzWsMap.put("message", "org.zaproxy.zap.extension.websocket.WebSocketMessageDTO");
        // Defined in
        // org.zaproxy.zap.extension.websocket.fuzz.processors.WebSocketFuzzerProcessorScript
        // not using directly as its in another add-on
        typeToClassMaps.put("websocketfuzzerprocessor", fuzzWsMap);

        // HTTP Sender
        HashMap<String, String> httpSenderMap = new HashMap<>();
        httpSenderMap.put("helper", "org.zaproxy.zap.extension.script.HttpSenderScriptHelper");
        httpSenderMap.put("msg", "org.parosproxy.paros.network.HttpMessage");
        typeToClassMaps.put(ExtensionScript.TYPE_HTTP_SENDER, httpSenderMap);

        // Passive Rules
        HashMap<String, String> passiveRuleMap = new HashMap<>();
        passiveRuleMap.put("msg", "org.parosproxy.paros.network.HttpMessage");
        passiveRuleMap.put("ps", "org.zaproxy.zap.extension.pscan.scanner.ScriptsPassiveScanner");
        passiveRuleMap.put("src", "net.htmlparser.jericho.Source");
        typeToClassMaps.put(ExtensionPassiveScan.SCRIPT_TYPE_PASSIVE, passiveRuleMap);

        // Payload Generator - none : has no parameters

        // Payload Processor
        HashMap<String, String> procMap = new HashMap<>();
        procMap.put("payload", "java.lang.String");
        // Defined in org.zaproxy.zap.extension.fuzz.payloads.processor.ScriptStringPayloadProcessor
        // not using directly as its in another add-on
        typeToClassMaps.put("payloadprocessor", procMap);

        // Proxy
        HashMap<String, String> proxyMap = new HashMap<>();
        proxyMap.put("msg", "org.parosproxy.paros.network.HttpMessage");
        typeToClassMaps.put(ExtensionScript.TYPE_PROXY, proxyMap);

        // Script Input Vector
        HashMap<String, String> inputVectorMap = new HashMap<>();
        inputVectorMap.put("helper", "org.parosproxy.paros.core.scanner.VariantCustom");
        inputVectorMap.put("msg", "org.parosproxy.paros.network.HttpMessage");
        typeToClassMaps.put(ExtensionActiveScan.SCRIPT_TYPE_VARIANT, inputVectorMap);

        // Standalone - none : has no parameters

        // Targeted
        HashMap<String, String> targetedMap = new HashMap<>();
        targetedMap.put("msg", "org.parosproxy.paros.network.HttpMessage");
        typeToClassMaps.put(ExtensionScript.TYPE_TARGETED, targetedMap);
    }

    public void insertText(String text) {
        String allText = textInput.getText();
        StringBuilder sb = new StringBuilder();
        int i = textInput.getCaretPosition();
        // Replace any chrs already typed
        sb.append(allText.substring(0, i - this.textBefore(allText, i).length()));
        sb.append(text);
        sb.append(allText.substring(i));
        textInput.setText(sb.toString());
        textInput.setCaretPosition(i + text.length());
    }

    private void closeMenu() {
        if (textPopupMenu != null) {
            textPopupMenu.setVisible(false);
            textPopupMenu = null;
        }
    }

    @Override
    public void keyPressed(KeyEvent e) {

        if (textPopupMenu != null && textPopupMenu.isVisible()) {
            if (e.getKeyCode() == KeyEvent.VK_DOWN || e.getKeyChar() == 65535) {
                e.consume();
                textPopupMenu.selectFirstMenu();
            } else if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
                closeMenu();
            } else if (e.getKeyCode() == KeyEvent.VK_BACK_SPACE) {
                char delChar = textInput.getText().charAt(textInput.getCaretPosition() - 1);
                if (delChar == '.') {
                    // Deleted the dot - close the menu
                    closeMenu();
                } else {
                    String txt = textBefore(textInput.getText(), textInput.getCaretPosition() - 1);
                    filterMenus(txt);
                }
            }
        }
    }

    private String textBefore(String text, int posn) {
        if (posn == 0) {
            // Start of the text area
            return "";
        }
        int j;
        for (j = posn - 1; j >= 0; j--) {
            char c = text.charAt(j);
            if (!Character.isAlphabetic(c)) {
                j += 1;
                break;
            }
        }
        if (j < 0) {
            return "";
        }
        return text.substring(j, posn);
    }

    private void filterMenus(String text) {
        textPopupMenu.filterMenus(text);
    }

    @Override
    public void keyTyped(KeyEvent e) {
        if (!enabled) {
            return;
        }
        Point p = textInput.getCaret().getMagicCaretPosition();

        if (textPopupMenu != null && textPopupMenu.isVisible()) {
            // filter based on text typed
            if (Character.isAlphabetic(e.getKeyChar())) {
                String txt =
                        textBefore(textInput.getText(), textInput.getCaretPosition())
                                + e.getKeyChar();
                filterMenus(txt);
            }
        }

        if (p != null) {
            if (textPopupMenu != null && textPopupMenu.isVisible()) {
                SwingUtilities.convertPointToScreen(p, textInput);
                textPopupMenu.setLocation(p.x, p.y + 20);
            } else {
                if (e.getKeyChar() == '.') {
                    int caretPosn = textInput.getCaretPosition();
                    if (caretPosn > 0) {
                        String var = textBefore(textInput.getText(), caretPosn);
                        if (var.length() > 0) {
                            // Do we have any mappings for this script type?
                            Map<String, String> map = this.typeToClassMaps.get(this.scriptType);
                            if (map == null) {
                                LOG.debug(
                                        "No autocomplete map for script type: {}", this.scriptType);
                            } else {
                                // Try to match the text against a variable name
                                String className = map.get(var);
                                if (className != null) {
                                    try {
                                        Class<?> c =
                                                ExtensionFactory.getAddOnLoader()
                                                        .loadClass(className);
                                        this.showMenuForClass(c, p);
                                    } catch (ClassNotFoundException e1) {
                                        LOG.error("Failed to find class {}", className, e1);
                                    }
                                }
                            }
                        } else {
                            // check for a close bracket to handled chained calls
                            char prevChar = textInput.getText().charAt(caretPosn - 1);
                            if (prevChar == ')') {
                                // Try to parse the call stack
                                if (this.lastReturnType != null) {
                                    this.showMenuForClass(this.lastReturnType, p);
                                }
                            }
                        }
                    }
                } else if (this.lastReturnType != null) {
                    // they've typed something else, too hard to parse the method names and params
                    // right now
                    this.lastReturnType = null;
                }
            }
        }
    }

    private void showMenuForClass(Class<?> c, Point p) {
        this.textPopupMenu = new ScriptAutoCompleteMenu(this);
        for (Method method : c.getMethods()) {
            if (Modifier.isPublic(method.getModifiers())) {
                textPopupMenu.addMenu(method);
            }
        }
        textPopupMenu.show(textInput, p.x, p.y + 20);
    }

    public void setLastReturnType(Class<?> returnType) {
        this.lastReturnType = returnType;
    }

    public void setScriptType(String typeName) {
        this.scriptType = typeName;
    }

    public void setEnabled(boolean enable) {
        this.enabled = enable;
    }
}
