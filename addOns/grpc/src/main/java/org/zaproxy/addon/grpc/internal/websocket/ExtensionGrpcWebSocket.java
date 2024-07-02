/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.grpc.internal.websocket;

import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.grpc.ExtensionGrpc;
import org.zaproxy.addon.grpc.internal.DecoderUtils;
import org.zaproxy.addon.grpc.internal.HttpPanelGrpcView;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.extension.websocket.ExtensionWebSocket;
import org.zaproxy.zap.extension.websocket.ui.httppanel.component.WebSocketComponent;
import org.zaproxy.zap.extension.websocket.ui.httppanel.models.ByteWebSocketPanelViewModel;
import org.zaproxy.zap.view.HttpPanelManager;

public class ExtensionGrpcWebSocket extends ExtensionAdaptor {

    public static final String NAME = "ExtensionGrpcWebSocket";
    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionGrpc.class, ExtensionWebSocket.class);

    public ExtensionGrpcWebSocket() {
        super(NAME);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        if (hasView()) {
            HttpPanelManager manager = HttpPanelManager.getInstance();
            manager.addRequestViewFactory(WebSocketComponent.NAME, new WebSocketGrpcViewFactory());
            manager.addResponseViewFactory(WebSocketComponent.NAME, new WebSocketGrpcViewFactory());
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        HttpPanelManager manager = HttpPanelManager.getInstance();
        manager.removeRequestViewFactory(WebSocketComponent.NAME, WebSocketGrpcViewFactory.NAME);
        manager.removeResponseViewFactory(WebSocketComponent.NAME, WebSocketGrpcViewFactory.NAME);
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("grpc.websocket.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("grpc.websocket.desc");
    }

    private static final class WebSocketGrpcViewFactory
            implements HttpPanelManager.HttpPanelViewFactory {
        public static final String NAME = "WebSocketGrpcViewFactory";

        @Override
        public String getName() {
            return NAME;
        }

        @Override
        public HttpPanelView getNewView() {
            return new HttpPanelGrpcView(
                    new ByteWebSocketPanelViewModel(), DecoderUtils.DecodingMethod.DIRECT);
        }

        @Override
        public Object getOptions() {
            return null;
        }
    }
}
