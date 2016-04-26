/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.viewstate;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.swing.JTable;
import javax.swing.JViewport;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.httppanel.component.split.request.RequestSplitComponent;
import org.zaproxy.zap.extension.httppanel.component.split.response.ResponseSplitComponent;
import org.zaproxy.zap.extension.httppanel.view.AbstractByteHttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.extension.httppanel.view.hex.ExtensionHttpPanelHexView;
import org.zaproxy.zap.extension.httppanel.view.hex.HttpPanelHexModel;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.AbstractHttpByteHttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.HttpPanelViewModelUtils;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.request.RequestBodyByteHttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.request.RequestByteHttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.request.RequestHeaderByteHttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.response.ResponseBodyByteHttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.response.ResponseByteHttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.response.ResponseHeaderByteHttpPanelViewModel;
import org.zaproxy.zap.extension.viewstate.ViewStateModel.ViewStateUpdatedListener;
import org.zaproxy.zap.extension.brk.BreakpointMessageHandler;
import org.zaproxy.zap.extension.brk.ExtensionBreak;
import org.zaproxy.zap.extension.httppanel.ComponentChangedEvent;
import org.zaproxy.zap.extension.httppanel.MessagePanelEventListener;
import org.zaproxy.zap.extension.httppanel.MessageViewSelectedEvent;
import org.zaproxy.zap.extension.httppanel.component.all.request.RequestAllComponent;
import org.zaproxy.zap.extension.httppanel.component.all.response.ResponseAllComponent;
import org.zaproxy.zap.view.HttpPanelManager;
import org.zaproxy.zap.view.HttpPanelManager.HttpPanelViewFactory;

import net.htmlparser.jericho.Attribute;
import net.htmlparser.jericho.Attributes;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;

public class ExtensionHttpPanelViewStateView extends ExtensionAdaptor {
	
	public static final int VS_ACTION_REQUEST = 1;
	public static final int VS_ACTION_RESPONSE = 2;
	private static final List<Class<?>> EXTENSION_DEPENDENCIES;
	static {
		// Prepare a list of Extensions on which this extension depends
		List<Class<?>> dependencies = new ArrayList<>(1);
		dependencies.add(ExtensionBreak.class);
		dependencies.add(ExtensionHttpPanelHexView.class);
		EXTENSION_DEPENDENCIES = Collections.unmodifiableList(dependencies);
	}
    private static Logger logger = Logger.getLogger(ExtensionHttpPanelViewStateView.class);
	public static final String NAME = "ExtensionHttpPanelViewStateView";
	public static final int PROXY_LISTENER_ORDER = 10;
	private ExtensionBreak eBreak;
	private boolean breakAvailableAndEnabled = false;
    private BreakpointMessageHandler breakpointMessageHandler;
    private HttpPanelViewStateView reqView;
    private HttpPanelViewStateView respView;
    private ViewStateModel reqModel;
    private ViewStateModel respModel;
	
	public ExtensionHttpPanelViewStateView() {
		super(NAME);
		initialize();
	}
	
	public ExtensionHttpPanelViewStateView(String name) {
        super(name);
        initialize();
    }

    private void initialize() {
        this.setName(NAME);
        this.setOrder(25);
	}
    
    private void initViewFactories() {
    	if (getView() != null) {
			HttpPanelManager.getInstance().addRequestViewFactory(RequestSplitComponent.NAME, new RequestSplitBodyViewStateViewFactory());
			HttpPanelManager.getInstance().addResponseViewFactory(ResponseSplitComponent.NAME, new ResponseSplitBodyViewStateViewFactory());
		}
    }
	
	@Override
	public void hook(ExtensionHook extensionHook) {
	    super.hook(extensionHook);
	    
	    // Register proxy listener
        //extensionHook.addProxyListener(this);
        
        if (getView() != null) {
        	eBreak = (ExtensionBreak) Control.getSingleton().getExtensionLoader().getExtension(ExtensionBreak.NAME);
	        if (eBreak == null || !eBreak.isEnabled()) {
	        	logger.warn("Could not load ExtensionBreak!");
	        } else {
	        	breakAvailableAndEnabled = true;
	        	breakpointMessageHandler = new BreakpointMessageHandler(eBreak.getBreakPanel());
	            breakpointMessageHandler.setEnabledBreakpoints(eBreak.getBreakpointsEnabledList());
	        }
        }
        
        initViewFactories();
	}
	
	@Override
	public boolean canUnload() {
		// Do not allow the unload until moved to an add-on.
		return false;
	}
	
	@Override
	public void unload() {
		if (getView() != null) {
			HttpPanelManager panelManager = HttpPanelManager.getInstance();
			panelManager.removeRequestViewFactory(RequestSplitComponent.NAME, RequestSplitBodyViewStateViewFactory.NAME);
			panelManager.removeRequestViews(
					RequestSplitComponent.NAME,
					HttpPanelViewStateView.NAME,
					RequestSplitComponent.ViewComponent.BODY);

			panelManager.removeResponseViewFactory(ResponseSplitComponent.NAME, ResponseSplitBodyViewStateViewFactory.NAME);
			panelManager.removeResponseViews(
					ResponseSplitComponent.NAME,
					HttpPanelViewStateView.NAME,
					ResponseSplitComponent.ViewComponent.BODY);
		}
	}

	private final class RequestSplitBodyViewStateViewFactory implements HttpPanelViewFactory {
		
		public static final String NAME = "RequestSplitBodyViewStateViewFactory";
		
		@Override
		public String getName() {
			return NAME;
		}
		
		@Override
		public HttpPanelView getNewView() {
			reqModel = new ViewStateModel(VS_ACTION_REQUEST, null);
			reqView = new HttpPanelViewStateView(reqModel, false);
			// Register listener on the view
			reqModel.setListener(reqView);
			return reqView;
		}

		@Override
		public Object getOptions() {
			return RequestSplitComponent.ViewComponent.BODY;
		}
	}

	private final class ResponseSplitBodyViewStateViewFactory implements HttpPanelViewFactory {
		
		public static final String NAME = "ResponseSplitBodyViewStateViewFactory";
		
		@Override
		public String getName() {
			return NAME;
		}
		
		@Override
		public HttpPanelView getNewView() {
			respModel = new ViewStateModel(VS_ACTION_RESPONSE, null);
			respView = new HttpPanelViewStateView(respModel, false);
			// Register listener on the view
			respModel.setListener(respView);
			return respView;
		}

		@Override
		public Object getOptions() {
			return ResponseSplitComponent.ViewComponent.BODY;
		}
	}

	@Override
    public String getAuthor() {
        return Constant.messages.getString("viewstate.author");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("viewstate.desc");
    }

    @Override
    public URL getURL() {
        try {
            return new URL(Constant.ZAP_EXTENSIONS_PAGE);
        } catch (MalformedURLException e) {
            return null;
        }
    }

	/**
	 * No database tables used, so all supported
	 */
	@Override
	public boolean supportsDb(String type) {
		return true;
	}
	
	/*
	 * May as well keep this around though the functionality is unnecessary (show/hide view in dropdown on break)
	 * 
	@Override
	public int getArrangeableListenerOrder() {
		return PROXY_LISTENER_ORDER;
	}
	
	@Override
	public boolean onHttpRequestSend(HttpMessage msg) {
		
		if (breakAvailableAndEnabled && breakpointMessageHandler.isBreakpoint(msg, true, false)) {
			if (reqModel.hasViewState(msg)) {
				reqView.setEnabled(true);
			} else {
				reqView.setEnabled(false);
			}
		}
		
		return true;
	}

	@Override
	public boolean onHttpResponseReceive(HttpMessage msg) {
		
		if (breakAvailableAndEnabled && breakpointMessageHandler.isBreakpoint(msg, false, false)) {
			if (respModel.hasViewState(msg)) {
				respView.setEnabled(true);
			} else {
				respView.setEnabled(false);
			}
		}
		
		return true;
	}
	*/
	
}

