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
package org.zaproxy.zap.extension.tokengen;

import javax.swing.SwingWorker;

import org.apache.log4j.Logger;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.params.HtmlParameterStats;

public class TokenGenerator extends SwingWorker<Void, Void> {
	
	private int numberTokens = 0;
	private HttpMessage httpMessage = null;
	private HttpSender httpSender = null;
	private HtmlParameterStats targetToken = null;
	private ExtensionTokenGen extension = null;
	private boolean stopGenerating = false;
	private boolean paused = false;
    private static Logger log = Logger.getLogger(TokenGenerator.class);

	private HttpSender getHttpSender() {
		if (httpSender == null) {
			httpSender = new HttpSender(Model.getSingleton().getOptionsParam().getConnectionParam(), true);

		}
		return httpSender;
	}

	@Override
	protected Void doInBackground() throws Exception {
		for (int i=0; i < numberTokens; i++) {
			while (paused && ! this.stopGenerating) {
				try {
					Thread.sleep (500);
				} catch (InterruptedException e) {
					// Ignore
				}
			}
			if (this.stopGenerating) {
				break;
			}

			HttpMessage msg = this.httpMessage.cloneRequest();

			try {
				msg.getRequestHeader().setHeader(HttpHeader.COOKIE, null);
				this.getHttpSender().sendAndReceive(msg, true);
			} catch (Exception e) {
				log.error(e.getMessage(), e);
			}
			this.extension.addTokenResult(msg, targetToken);
		}
		this.extension.generatorStopped(this);

		return null;
	}

	public void setNumberTokens(int numberTokens) {
		this.numberTokens = numberTokens;
	}

	public void setHttpMessage(HttpMessage httpMessage) {
		this.httpMessage = httpMessage;
	}

	public void setTargetToken(HtmlParameterStats targetToken) {
		this.targetToken = targetToken;
	}

	public void stopGenerating() {
		this.stopGenerating = true;
	}

	public void setExtension(ExtensionTokenGen extension) {
		this.extension = extension;
	}

	public boolean isPaused() {
		return paused;
	}

	public void setPaused(boolean paused) {
		this.paused = paused;
	}

}
