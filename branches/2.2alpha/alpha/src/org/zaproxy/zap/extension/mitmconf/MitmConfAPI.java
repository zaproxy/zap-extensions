/*
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
package org.zaproxy.zap.extension.mitmconf;

import java.io.IOException;
import java.io.InputStream;

import net.sf.json.JSONObject;

import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiOther;

public class MitmConfAPI extends ApiImplementor {

	private static Logger logger = Logger.getLogger(MitmConfAPI.class);

	private static final String PREFIX = "mitm";

	private static final String OTHER_MITM = "mitm";
	private static final String OTHER_MANIFEST = "manifest";
	private static final String OTHER_SERVICE = "service";
	private static final String OTHER_FIREFOX_ADDON = "ringleader.xpi";
	
	/*
	private static final String PROXY_PAC = "/proxy.pac";
	private static final String ROOT_CERT = "/OTHER/core/other/rootcert/";
	private static final String FIREFOX_ADDON = "OTHER/" + PREFIX + "/other/" + OTHER_FIREFOX_ADDON;
	*/

	public MitmConfAPI() {
		
		this.addApiOthers(new ApiOther(OTHER_MITM));
		this.addApiOthers(new ApiOther(OTHER_MANIFEST));
		this.addApiOthers(new ApiOther(OTHER_SERVICE));
		this.addApiOthers(new ApiOther(OTHER_FIREFOX_ADDON));

		this.addApiShortcut(OTHER_MITM);
		this.addApiShortcut(OTHER_MANIFEST);

	}

	@Override
	public String getPrefix() {
		return PREFIX;
	}

	
	@Override
	public HttpMessage handleApiOther(HttpMessage msg, String name,
			JSONObject params) throws ApiException {
		String root = "http://" + msg.getRequestHeader().getHostName() + ":" + msg.getRequestHeader().getHostPort();

		if (OTHER_MITM.equals(name)) {
			try {
				String welcomePage = this.getStringReource("resource/welcome.html");
				// Replace the dynamic parts
				welcomePage = welcomePage.replace("{{ROOT}}", root);
				// Replace the i18n strings
				welcomePage = welcomePage.replace("{{MSG.TITLE}}", Constant.messages.getString("mitmconf.title"));
				welcomePage = welcomePage.replace("{{MSG.HEADER}}", Constant.messages.getString("mitmconf.header"));
				welcomePage = welcomePage.replace("{{MSG.INTRO1}}", Constant.messages.getString("mitmconf.intro1"));
				welcomePage = welcomePage.replace("{{MSG.INTRO2}}", Constant.messages.getString("mitmconf.intro2"));
				welcomePage = welcomePage.replace("{{MSG.SETUP1}}", Constant.messages.getString("mitmconf.setup1"));
				welcomePage = welcomePage.replace("{{MSG.SETUP2}}", Constant.messages.getString("mitmconf.setup2"));
				welcomePage = welcomePage.replace("{{MSG.PROGRESS}}", Constant.messages.getString("mitmconf.progress"));
				welcomePage = welcomePage.replace("{{MSG.FAILURE}}", Constant.messages.getString("mitmconf.failure"));
				welcomePage = welcomePage.replace("{{MSG.SUCCESS}}", Constant.messages.getString("mitmconf.success"));
				welcomePage = welcomePage.replace("{{MSG.ACTIVATED}}", Constant.messages.getString("mitmconf.activated"));
				welcomePage = welcomePage.replace("{{MSG.BUTTON}}", Constant.messages.getString("mitmconf.button"));

				/*
				// TODO - this seems to detect Firefox fine...
				String userAgent = msg.getRequestHeader().getHeader(HttpHeader.USER_AGENT);
				if (userAgent.toLowerCase().indexOf("firefox") >= 0) {
					// It looks like firefox
				}
				*/
				
				msg.setResponseHeader(
						"HTTP/1.1 200 OK\r\n" +
						"Pragma: no-cache\r\n" +
						"Cache-Control: no-cache\r\n" + 
						"Access-Control-Allow-Origin: *\r\n" + 
						"Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n" + 
						"Access-Control-Allow-Headers: ZAP-Header\r\n" + 
						"Content-Length: " + welcomePage.length() + 
						"\r\nContent-Type: text/html;");
				
		    	msg.setResponseBody(welcomePage);
		    	
			} catch (Exception e) {
				logger.error(e.getMessage(), e);
			}
			return msg;
			
		} else if (OTHER_MANIFEST.equals(name)) {
			try {
				String manifest = this.getStringReource("resource/manifest.json");
				// Replace the dynamic parts
				manifest = manifest.replace("{{ROOT}}", root);

				msg.setResponseHeader(
						"HTTP/1.1 200 OK\r\n" +
						"Pragma: no-cache\r\n" +
						"Cache-Control: no-cache\r\n" + 
						"Access-Control-Allow-Origin: *\r\n" + 
						"Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n" + 
						"Access-Control-Allow-Headers: ZAP-Header\r\n" + 
						"Content-Length: " + manifest.length() + 
						"\r\nContent-Type: application/json");
				
		    	msg.setResponseBody(manifest);
		    	
			} catch (Exception e) {
				logger.error(e.getMessage(), e);
			}
			return msg;
			
		} else if (OTHER_SERVICE.equals(name)) {
			try {
				String service = this.getStringReource("resource/service.json");
				// Replace the dynamic parts
				service = service.replace("{{ROOT}}", root);

				msg.setResponseHeader(
						"HTTP/1.1 200 OK\r\n" +
						"Pragma: no-cache\r\n" +
						"Cache-Control: no-cache\r\n" + 
						"Access-Control-Allow-Origin: *\r\n" + 
						"Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n" + 
						"Access-Control-Allow-Headers: ZAP-Header\r\n" + 
						"Content-Length: " + service.length() + 
						"\r\nContent-Type: application/json");
				
		    	msg.setResponseBody(service);
		    	
			} catch (Exception e) {
				logger.error(e.getMessage(), e);
			}
			return msg;
			
		} else if (OTHER_FIREFOX_ADDON.equals(name)) {
			InputStream in = null;
			try {
				in = this.getClass().getResourceAsStream("resource/" + OTHER_FIREFOX_ADDON);

				int numRead=0;
				int length = 0;
                byte[] buf = new byte[1024];
                while((numRead = in.read(buf)) != -1){
                	msg.getResponseBody().append(buf, numRead);
                	length += numRead;
                }

				msg.setResponseHeader(
						"HTTP/1.1 200 OK\r\n" +
						"Content-Type: application/x-xpinstall" +
						"Accept-Ranges: byte" +
						"Pragma: no-cache\r\n" +
						"Cache-Control: no-cache\r\n" + 
						"Access-Control-Allow-Origin: *\r\n" + 
						"Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n" + 
						"Access-Control-Allow-Headers: ZAP-Header\r\n" + 
						"Content-Length: " + length + "\r\n"); 
				
			} catch (Exception e) {
				logger.error(e.getMessage(), e);
				throw new ApiException(ApiException.Type.INTERNAL_ERROR);
			} finally {
				if (in != null) {
					try {
						in.close();
					} catch (IOException e) {
						// Ignore
					}
				}
			}
			
			return msg;
		} else {
			throw new ApiException(ApiException.Type.BAD_OTHER);
		}
	}
	
	private String getStringReource(String resourceName) throws ApiException {
		InputStream in = null;
		StringBuilder sb = new StringBuilder();
		try {
			in = this.getClass().getResourceAsStream(resourceName);
			int numRead=0;
            byte[] buf = new byte[1024];
            while((numRead = in.read(buf)) != -1){
            	sb.append(new String(buf, 0, numRead));
            }
            return sb.toString();
			
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			throw new ApiException(ApiException.Type.INTERNAL_ERROR);
		} finally {
			if (in != null) {
				try {
					in.close();
				} catch (IOException e) {
					// Ignore
				}
			}
		}
	}

	@Override
	public HttpMessage handleShortcut(HttpMessage msg)  throws ApiException {
		try {
			if (msg.getRequestHeader().getURI().getPath().startsWith("/" + OTHER_MITM)) {
				return this.handleApiOther(msg, OTHER_MITM, null);
			} else if (msg.getRequestHeader().getURI().getPath().startsWith("/" + OTHER_MANIFEST)) {
				return this.handleApiOther(msg, OTHER_MANIFEST, null);
			}
		} catch (URIException e) {
			logger.error(e.getMessage(), e);
			throw new ApiException(ApiException.Type.INTERNAL_ERROR);
		}
		throw new ApiException (ApiException.Type.URL_NOT_FOUND, msg.getRequestHeader().getURI().toString());
	}
}
