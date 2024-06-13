package org.zaproxy.addon.grpc.internal;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.grpc.ExtensionGrpc;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.extension.websocket.ExtensionWebSocket;
import org.zaproxy.zap.extension.websocket.ui.httppanel.component.WebSocketComponent;
import org.zaproxy.zap.extension.websocket.ui.httppanel.models.ByteWebSocketPanelViewModel;
import org.zaproxy.zap.view.HttpPanelManager;

import java.util.List;

public class ExtensionGrpcWebSocket extends ExtensionAdaptor {

    public static final String NAME = "ExtensionGrpcWebSocket";

    public ExtensionGrpcWebSocket() {
        super(NAME);
    }

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionGrpc.class, ExtensionWebSocket.class);


    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        if (hasView()) {
            HttpPanelManager manager = HttpPanelManager.getInstance();
            manager.addRequestViewFactory(
                    WebSocketComponent.NAME, new WebSocketGrpcViewFactory());
            manager.addResponseViewFactory(
                    WebSocketComponent.NAME, new WebSocketGrpcViewFactory());

        }

    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        HttpPanelManager manager = HttpPanelManager.getInstance();
        manager.removeRequestViewFactory(WebSocketComponent.NAME, WebSocketGrpcViewFactory.NAME );
        manager.removeResponseViewFactory(WebSocketComponent.NAME, WebSocketGrpcViewFactory.NAME );
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
            return new HttpPanelGrpcView(new ByteWebSocketPanelViewModel());
        }

        @Override
        public Object getOptions() {
            return null;
        }
    }



}
