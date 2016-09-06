/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP development team
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
package org.zaproxy.zap.extension.wappalyzer;

import java.util.Date;
import java.util.List;
import java.util.Map;

import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PassiveScanner;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class WappalyzerPassiveScanner implements PassiveScanner {

	private ExtensionWappalyzer extension = null;
	private List<Application> applications = null;

	private static final Logger LOGGER = Logger.getLogger(WappalyzerPassiveScanner.class);

	public WappalyzerPassiveScanner() {
		super();
	}
	
	@Override
	public String getName() {
		return Constant.messages.getString("wappalyzer.scanner");
	}

	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		// do nothing
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		HistoryReference href = msg.getHistoryRef();
		if (href == null) {
			// Ignore
		} else {
			SiteNode node = href.getSiteNode();
			if (node != null && node.getPastHistoryReference().size() == 0) {
				// No previous references - scan this page
				// we dont scan pages we've already seen for performance reasons
				Date start = new Date();
				for (Application app : this.getApps()) {
					boolean found = false;
					String url = msg.getRequestHeader().getURI().toString();
					for (AppPattern p : app.getUrl()) {
						if (p.getPattern().matcher(url).find()) {
							LOGGER.debug("WAPP URL matched " + app.getName());
							found = true;
							break;
						}
					}
					if (! found) {
						for (Map<String, AppPattern> sp : app.getHeaders()) {
							for (Map.Entry<String, AppPattern> entry : sp.entrySet()) {
								String header = msg.getResponseHeader().getHeader(entry.getKey());
								if (header != null) {
									if (entry.getValue().getPattern().matcher(header).find()) {
										LOGGER.debug("WAPP header matched " + app.getName());
										found = true;
										break;
									}
								}
							}
						}
					}
					if (! found) {
						String body = msg.getResponseBody().toString();
						for (AppPattern p : app.getHtml()) {
							if (p.getPattern().matcher(body).find()) {
								LOGGER.debug("WAPP body matched " + app.getName());
								found = true;
								break;
							}
						}
					}
					if (! found) {
						List<Element> metaElements = source.getAllElements(HTMLElementName.META);
						for (Element metaElement : metaElements) {
							for (Map<String, AppPattern> sp : app.getMetas()) {
								for (Map.Entry<String, AppPattern> entry : sp.entrySet()) {
									String name = metaElement.getAttributeValue("name");
									String content = metaElement.getAttributeValue("content");
									if (name != null && content != null) {
										if (name.equals(entry.getKey())
												&& entry.getValue().getPattern().matcher(content).find()) {
											LOGGER.debug("WAPP meta matched " + app.getName());
											found = true;
											break;
										}
									}
								}
							}
						}
					}
					if (! found) {
						String body = msg.getResponseBody().toString();
						for (AppPattern p : app.getScript()) {
							if (p.getPattern().matcher(body).find()) {
								LOGGER.debug("WAPP script matched " + app.getName());
								found = true;
								break;
							}
							
						}
					}
					if (found) {
						String site = msg.getRequestHeader().getHostName() + ":" + msg.getRequestHeader().getHostPort();
						LOGGER.debug("WAPP adding " + app.getName() + " to " + site);
						this.extension.addApplicationsToSite(site, app);
					}
				}
					LOGGER.debug("WAPP took " + (new Date().getTime() - start.getTime()));
			}
		}
	}

	private List<Application> getApps() {
		if (applications == null) {
			applications = this.getExtension().getApplications();
		}
		return applications;
	}

	private ExtensionWappalyzer getExtension() {
		if (extension == null) {
			extension = (ExtensionWappalyzer) Control.getSingleton().getExtensionLoader().getExtension(ExtensionWappalyzer.NAME);
		}
		return extension;
	}
	
	@Override
	public void setParent(PassiveScanThread parent) {
		// Does not apply.
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

	@Override
	public void setEnabled(boolean enabled) {
		// Does not apply.
	}

	@Override
	public AlertThreshold getLevel() {
		return AlertThreshold.MEDIUM;
	}

	@Override
	public void setLevel(AlertThreshold level) {
		// Does not apply.
	}

	@Override
	public boolean appliesToHistoryType(int historyType) {
		return PluginPassiveScanner.getDefaultHistoryTypes().contains(historyType);
	}

}