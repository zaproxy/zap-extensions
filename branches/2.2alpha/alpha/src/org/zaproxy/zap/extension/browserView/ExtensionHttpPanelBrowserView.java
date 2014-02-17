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
package org.zaproxy.zap.extension.browserView;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.httppanel.component.all.request.RequestAllComponent;
import org.zaproxy.zap.extension.httppanel.component.all.response.ResponseAllComponent;
import org.zaproxy.zap.extension.httppanel.component.split.response.ResponseSplitComponent;
import org.zaproxy.zap.extension.httppanel.view.DefaultHttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.view.HttpPanelManager;
import org.zaproxy.zap.view.HttpPanelManager.HttpPanelViewFactory;

public class ExtensionHttpPanelBrowserView extends ExtensionAdaptor {
	
	public static final String NAME = "ExtensionHttpPanelBrowserView";
	
	public ExtensionHttpPanelBrowserView() {
		super(NAME);
	}

	@Override
	public void hook(ExtensionHook extensionHook) {
	    super.hook(extensionHook);
		if (getView() != null) {
			HttpPanelManager panelManager = HttpPanelManager.getInstance();
			panelManager.addResponseViewFactory(ResponseSplitComponent.NAME, new ResponseBrowserViewFactory());
			panelManager.addResponseViewFactory(ResponseAllComponent.NAME, new ResponseBrowserViewFactory2());
		}
	}
	
	@Override
	public boolean canUnload() {
		return true;
	}
	
	@Override
	public void unload() {
		if (getView() != null) {
			HttpPanelManager panelManager = HttpPanelManager.getInstance();
			panelManager.removeResponseViewFactory(ResponseSplitComponent.NAME, ResponseBrowserViewFactory.NAME);
			panelManager.removeResponseViews(
					ResponseSplitComponent.NAME,
					ResponseBrowserView.NAME,
					ResponseSplitComponent.ViewComponent.BODY);
			panelManager.removeResponseViewFactory(RequestAllComponent.NAME, ResponseBrowserViewFactory2.NAME);
			panelManager.removeResponseViews(ResponseAllComponent.NAME, ResponseBrowserViewFactory2.NAME, null);

		}
	}
	
	private static final class ResponseBrowserViewFactory implements HttpPanelViewFactory {
		
		public static final String NAME = "ResponseBrowserViewFactory";
		
		@Override
		public String getName() {
			return NAME;
		}
		
		@Override
		public HttpPanelView getNewView() {
			return new ResponseBrowserView(new DefaultHttpPanelViewModel());
		}

		@Override
		public Object getOptions() {
			return ResponseSplitComponent.ViewComponent.BODY;
		}
	}

	private static final class ResponseBrowserViewFactory2 implements HttpPanelViewFactory {
		
		public static final String NAME = "ResponseBrowserViewFactory2";
		
		@Override
		public String getName() {
			return NAME;
		}
		
		@Override
		public HttpPanelView getNewView() {
			return new ResponseBrowserView(new DefaultHttpPanelViewModel());
		}

		@Override
		public Object getOptions() {
			return null;
		}
	}

	
	
	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}
}

