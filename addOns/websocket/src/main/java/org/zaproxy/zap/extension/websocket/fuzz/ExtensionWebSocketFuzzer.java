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
package org.zaproxy.zap.extension.websocket.fuzz;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.ImageIcon;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ViewDelegate;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.extension.fuzz.ExtensionFuzz;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacers;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.websocket.ExtensionWebSocket;
import org.zaproxy.zap.extension.websocket.WebSocketMessage;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.WebSocketObserver;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.WebSocketProxy.State;
import org.zaproxy.zap.extension.websocket.fuzz.messagelocations.TextWebSocketMessageLocationReplacerFactory;
import org.zaproxy.zap.extension.websocket.fuzz.processors.FuzzerWebSocketMessageScriptProcessorAdapterUIHandler;
import org.zaproxy.zap.extension.websocket.fuzz.processors.WebSocketFuzzerProcessorScript;
import org.zaproxy.zap.extension.websocket.ui.WebSocketPanel;

public class ExtensionWebSocketFuzzer extends ExtensionAdaptor {

    private static final ImageIcon WEBSOCKET_FUZZER_PROCESSOR_SCRIPT_ICON =
            new ImageIcon(ZAP.class.getResource("/resource/icon/16/script-fuzz.png"));

    private static final List<Class<? extends Extension>> DEPENDENCIES;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(2);
        dependencies.add(ExtensionFuzz.class);
        dependencies.add(ExtensionWebSocket.class);
        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    private WebSocketFuzzerHandler websocketFuzzerHandler;

    private ScriptType scriptType;

    private TextWebSocketMessageLocationReplacerFactory replacer;

    private AllChannelObserver allChannelObserver;

    public ExtensionWebSocketFuzzer() {
        super("ExtensionWebSocketFuzzer");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("websocket.fuzzer.description");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void init() {
        websocketFuzzerHandler = new WebSocketFuzzerHandler();
        replacer = new TextWebSocketMessageLocationReplacerFactory();

        MessageLocationReplacers.getInstance().addReplacer(WebSocketMessageDTO.class, replacer);
    }

    @Override
    public void initView(ViewDelegate view) {
        super.initView(view);

        ExtensionScript extensionScript =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        if (extensionScript != null) {
            scriptType =
                    new ScriptType(
                            WebSocketFuzzerProcessorScript.TYPE_NAME,
                            "websocket.fuzzer.script.type.fuzzerprocessor",
                            WEBSOCKET_FUZZER_PROCESSOR_SCRIPT_ICON,
                            true,
                            true);
            extensionScript.registerScriptType(scriptType);

            websocketFuzzerHandler.addFuzzerMessageProcessorUIHandler(
                    new FuzzerWebSocketMessageScriptProcessorAdapterUIHandler(extensionScript));
        }
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        ExtensionFuzz extensionFuzz =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionFuzz.class);
        extensionFuzz.addFuzzerHandler(websocketFuzzerHandler);

        if (getView() != null) {
            // Disable for now, there are no places where it would be used
            // extensionHook.getHookMenu()
            //       .addPopupMenuItem(new WebSocketFuzzAttackPopupMenuItem(extensionFuzz,
            // websocketFuzzerHandler));

            ExtensionWebSocket extensionWebSocket =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionWebSocket.class);
            extensionWebSocket.addAllChannelObserver(getAllChannelObserver());
        }
    }

    @Override
    public void unload() {
        super.unload();

        ExtensionFuzz extensionFuzz =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionFuzz.class);
        extensionFuzz.removeFuzzerHandler(websocketFuzzerHandler);

        ExtensionWebSocket extensionWebSocket =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionWebSocket.class);
        extensionWebSocket.removeAllChannelObserver(getAllChannelObserver());

        if (getView() != null) {
            ExtensionScript extensionScript =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
            if (extensionScript != null) {
                extensionScript.removeScriptType(scriptType);
            }
        }
        MessageLocationReplacers.getInstance().removeReplacer(WebSocketMessageDTO.class, replacer);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    public <
                    T1 extends WebSocketFuzzerMessageProcessor,
                    T2 extends WebSocketFuzzerMessageProcessorUI<T1>>
            void addFuzzerMessageProcessorUIHandler(
                    WebSocketFuzzerMessageProcessorUIHandler<T1, T2> handler) {
        websocketFuzzerHandler.addFuzzerMessageProcessorUIHandler(handler);
    }

    public <
                    T1 extends WebSocketFuzzerMessageProcessor,
                    T2 extends WebSocketFuzzerMessageProcessorUI<T1>>
            void removeFuzzerMessageProcessorUIHandler(
                    WebSocketFuzzerMessageProcessorUIHandler<T1, T2> handler) {
        websocketFuzzerHandler.removeFuzzerMessageProcessorUIHandler(handler);
    }

    private AllChannelObserver getAllChannelObserver() {
        if (allChannelObserver == null) {
            allChannelObserver = new AllChannelObserver();
        }
        return allChannelObserver;
    }

    protected Map<Integer, WebSocketProxy> getConnectedProxies() {
        return getAllChannelObserver().getConnectProxies();
    }

    private static class AllChannelObserver implements WebSocketObserver {

        private final Map<Integer, WebSocketProxy> connectedProxies;

        public AllChannelObserver() {
            connectedProxies = new HashMap<>();
        }

        @Override
        public int getObservingOrder() {
            return WebSocketPanel.WEBSOCKET_OBSERVING_ORDER + 15;
        }

        @Override
        public void onStateChange(State state, WebSocketProxy proxy) {
            if (state.equals(WebSocketProxy.State.OPEN)) {
                connectedProxies.put(proxy.getChannelId(), proxy);
            } else if (state.equals(WebSocketProxy.State.CLOSING)) {
                connectedProxies.remove(proxy.getChannelId());
            }
        }

        protected Map<Integer, WebSocketProxy> getConnectProxies() {
            return connectedProxies;
        }

        @Override
        public boolean onMessageFrame(int channelId, WebSocketMessage message) {
            return true;
        }
    }
}
