/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2016 The ZAP Development Team
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

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.AbstractHttpByteHttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.HttpPanelViewModelUtils;
import org.zaproxy.zap.extension.viewstate.zap.utils.ASPViewState;
import org.zaproxy.zap.extension.viewstate.zap.utils.JSFViewState;
import org.zaproxy.zap.extension.viewstate.zap.utils.ViewState;
import org.zaproxy.zap.model.StandardParameterParser;

import net.htmlparser.jericho.Attribute;
import net.htmlparser.jericho.Attributes;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;

public class ViewStateModel extends AbstractHttpByteHttpPanelViewModel {

	private static Logger logger = Logger.getLogger(ViewStateModel.class);
	public static final int VS_ACTION_REQUEST = 1;
	public static final int VS_ACTION_RESPONSE = 2;
	private ArrayList<ViewState> viewstateParams = new ArrayList<ViewState>();
	private ViewStateUpdatedListener vsListener;
	private String viewstateType;
	private int modelAction;
	
	public ViewStateModel(int action, ViewStateUpdatedListener listener) {
		// Setup ViewState params to look for
        viewstateParams.add(new ViewState(null, ASPViewState.KEY, "__VIEWSTATE"));
        // For chunked ASP ViewStates
        viewstateParams.add(new ViewState(null, ASPViewState.KEY, "__VIEWSTATEFIELDCOUNT"));
        // For JSF ViewStates
        viewstateParams.add(new ViewState(null, JSFViewState.KEY, "javax.faces.ViewState")); 
        // Set the action for the model (request/response)
        modelAction = action;
        // Set the ViewState listener
        vsListener = listener;
	}
	
	public ViewState getViewStateParam(String body) {

		ViewState viewState = null;
		for (ViewState vsp : viewstateParams) {
			String val = getParamValue(body, vsp.getName());
			if (val != null) {
				logger.debug("Found ViewState param: " + vsp.getName() + ". Type: " + vsp.getType());
				if (modelAction == VS_ACTION_REQUEST) {
					String decVal;
					try {
						// URL decode value first
						decVal = URLDecoder.decode(val, "UTF-8");
					} catch (Exception e) {
						logger.error("Could not URL decode ViewState", e);
						return null;
					}
					if (vsp.getType().equalsIgnoreCase(ASPViewState.KEY)) {
						viewState = new ASPViewState(decVal, vsp.getName());
					}
					if (vsp.getType().equalsIgnoreCase(JSFViewState.KEY)) {
						viewState = new JSFViewState(decVal, vsp.getName());
					}
				} else {
					if (vsp.getType().equalsIgnoreCase(ASPViewState.KEY)) {
						viewState = ASPViewState.getFromSource(new Source(body));
					}
					if (vsp.getType().equalsIgnoreCase(JSFViewState.KEY)) {
						viewState = new JSFViewState(val, vsp.getName());
					}
				}
			}
		}
		
		return viewState;
		
	}
	
	public Attributes getParam(String body, String paramName) {
		
		Attributes param = null;
		Source src = new Source(body);
		List<Element> formElements = src.getAllElements(HTMLElementName.FORM);
		
		if (formElements != null && formElements.size() > 0) {
			// Loop through all of the FORM tags
			logger.debug("Found " + formElements.size() + " forms");
			
			for (Element formElement : formElements) {
				List<Element> elements = formElement.getAllElements();
				
				if (elements != null && elements.size() > 0) {
					// Loop through all of the elements
					logger.debug("Found " + elements.size() + " inputs");
					for (Element element : elements) {
						Attributes atts = element.getAttributes();
						try {
							//  Get attr name
							Attribute name = atts.get("name");
							if (name != null) {
								if (name.getValue().equals(paramName)) {
									param = atts;
								}
							}
						} catch (Exception e) {
							logger.debug("Couldnt get name attribute of parameter", e);
						}
					}
				}
			}
		}
		
		return param;
		
	}
	
	public String getParamValue(String body, String paramName) {

		if (modelAction == VS_ACTION_REQUEST) {
			String param = null;
			StandardParameterParser spp = new StandardParameterParser();
			Map<String, String> params = spp.parse(body);
			for (Map.Entry<String, String> p : params.entrySet()) {
				if (p.getKey().equalsIgnoreCase(paramName)) {
					param = p.getValue();
				}
			}
			return param;
		} else {
			Attributes param = getParam(body, paramName);
			if (param != null) {
				Attribute val = param.get("value");
				if (val != null) {
					return val.getValue();
				} else {
					return null;
				}
			} else {
				return null;
			}
		}
		
	}
	
	@Override
	public byte[] getData() {
		
		if (httpMessage == null) {
			return new byte[0];
		}
		
		// Check for ViewState params and send data to panel if found
		String data = getModelData(httpMessage);
		ViewState vs = getViewStateParam(data);
		if (vs != null) {
			if (vsListener != null) {
				vsListener.viewStateUpdated(vs);
			}
			viewstateType = vs.getType();
			byte[] decoded = vs.getDecodedValue();
			if (decoded != null) {
				return decoded;
			} else {
				return new byte[0];
			}
		} else {
			if (vsListener != null) {
				vsListener.viewStateUpdated(null);
			}
			viewstateType = null;
			return new byte[0];
		}
		
	}

	@Override
	public void setData(byte[] data) {
		
		if (httpMessage == null) {
			return;
		}
		
		if (data.length > 0) {
			// Check for modification
			String origData = getModelData(httpMessage);
			ViewState vs = getViewStateParam(origData);
			if (vs != null) {
				String origViewState = vs.getDecodedValue().toString();
				String newViewState = new String(data);
				// Only update if its changed
				if (!newViewState.equalsIgnoreCase(origViewState)) {
					logger.info("Setting ViewState data to: " + newViewState);
					// Encode and update original HttpMessage param
					String newEncViewState = vs.getEncodedValue(data);
					updateParam(vs.getName(), newEncViewState);
				}
			}
		}
	}
	
	private boolean paramInList(TreeSet<HtmlParameter> paramList, String paramName) {
		boolean inList = false;
		for (HtmlParameter param : paramList) {
			if (param.getName().equalsIgnoreCase(paramName)) {
				inList = true;
			}
		}
		return inList;
	}
	
	private TreeSet<HtmlParameter> updateParamList(TreeSet<HtmlParameter> paramList, String paramName, String paramVal) {
		TreeSet<HtmlParameter> updatedList = new TreeSet<HtmlParameter>();
		for (HtmlParameter param : paramList) {
			if (param.getName().equalsIgnoreCase(paramName)) {
				// Update
				param.setValue(paramVal);
			} 
			// Just add the rest
			updatedList.add(param);
		}
		return updatedList;
	}
	
	private void updateParam(String name, String value) {
		//TODO: Still need logic to recreate chunked view states
		if (name.equalsIgnoreCase("__VIEWSTATEFIELDCOUNT")) {
			return;
		}
		// Overwrite original data
		if (modelAction == VS_ACTION_REQUEST) {
			try {
				// URL encode value
				value = URLEncoder.encode(value, "UTF-8");
			} catch (Exception e) {
				logger.error("Could not URL encode ViewState", e);
				return;
			}
			if (paramInList(httpMessage.getUrlParams(), name)) {
				TreeSet<HtmlParameter> updatedList = updateParamList(httpMessage.getUrlParams(), name, value);
				httpMessage.getRequestHeader().setGetParams(updatedList);
				HttpPanelViewModelUtils.updateRequestContentLength(httpMessage);
			}
			if (paramInList(httpMessage.getFormParams(), name)) {
				TreeSet<HtmlParameter> updatedList = updateParamList(httpMessage.getFormParams(), name, value);
				httpMessage.getRequestBody().setFormParams(updatedList);
				HttpPanelViewModelUtils.updateRequestContentLength(httpMessage);
			}
		} else {
			Pattern pattern = Pattern.compile("<input([\\s\\w=\"'/+]+)name=[\"']" + name + "[\"']([\\s\\w=\"'/+]+)>");
			Matcher matcher = pattern.matcher(httpMessage.getResponseBody().toString());
			if (matcher.find()) {
				String replacement = "<input type=\"hidden\" name=\"" + name + "\" id=\"" + name + "\" value=\"" + value + "\" />";
				String updatedBody = matcher.replaceAll(replacement);
				httpMessage.getResponseBody().setBody(updatedBody);
				HttpPanelViewModelUtils.updateResponseContentLength(httpMessage);
			}
		}
	}
	
	private String getModelData(HttpMessage msg) {
		// Get the right data depending on request/response
		if (modelAction == VS_ACTION_REQUEST) {
			try {
				return msg.getRequestHeader().getURI().getQuery() + "&" + msg.getRequestBody().toString();
			} catch (Exception e) {
				return msg.getRequestBody().toString();
			}
		} else {
			return msg.getResponseHeader().toString() + msg.getResponseBody().toString();
		}
	}
	
	public String getViewStateType() {
		return viewstateType;
	}
	
	public void setListener(ViewStateUpdatedListener listener) {
		vsListener = listener;
	}
	
	public boolean hasViewState(HttpMessage msg) {
		String data = getModelData(msg);
		ViewState vs = getViewStateParam(data);
		if (vs != null) {
			return true;
		} else {
			return false;
		}
	}
	
	public interface ViewStateUpdatedListener {
		public void viewStateUpdated(ViewState vs);
	}

}