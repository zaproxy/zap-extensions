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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import net.sf.json.JSONObject;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiOther;

public class MitmConfAPI extends ApiImplementor {

	private static Logger logger = Logger.getLogger(MitmConfAPI.class);

	private static final String PREFIX = "mitm";

	private static final String OTHER_MITM = "mitm";
	private static final String OTHER_MANIFEST = "manifest";
	private static final String OTHER_FIREFOX_ADDON = "gclimitm.xpi";
	
	private static final String PROXY_PAC = "/proxy.pac";
	private static final String ROOT_CERT = "/OTHER/core/other/rootcert/";
	private static final String FIREFOX_ADDON = "OTHER/" + PREFIX + "/other/" + OTHER_FIREFOX_ADDON;

	public MitmConfAPI() {
		
		this.addApiOthers(new ApiOther(OTHER_MITM));
		this.addApiOthers(new ApiOther(OTHER_MANIFEST));
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
				// Copied from as for WebUI.handleRequest(..)
				String manifestUrl = root + "/" + OTHER_MANIFEST;
				String firefoxAddonUrl = root + "/" + FIREFOX_ADDON;
				
				StringBuilder sb = new StringBuilder();
				/*
				sb.append("<head>\n");
				sb.append("<title>");
				sb.append(Constant.messages.getString("api.html.title"));
				sb.append("</title>\n");
				sb.append("</head>\n");
				sb.append("<body>\n");
				sb.append(Constant.messages.getString("api.home.topmsg"));
				
				sb.append("<b>Note: This is a temporary add-on for testing MITM configuration :) </b><br>");
				
				sb.append("  <button id=\"btn\">Click to setup!</button><br>");
				
				sb.append("<b>The manifest is at: <a href=\"" + manifestUrl + "\">" + manifestUrl + "</a> </b><br>");
				sb.append("<b>The Firefox add-on is at: <a href=\"" + firefoxAddonUrl + "\">" + firefoxAddonUrl + "</a> </b><br>");
				
				sb.append(Constant.messages.getString("api.home.proxypac"));
				sb.append(Constant.messages.getString("api.home.links.header"));
				if (API.getInstance().isEnabled()) {
					sb.append(Constant.messages.getString("api.home.links.api.enabled"));
				} else {
					sb.append(Constant.messages.getString("api.home.links.api.disabled"));
				}
				sb.append(Constant.messages.getString("api.home.links.online"));
				sb.append("</body>\n");
				
				sb.append("<script>\n");
				sb.append("	var click = function(event) {\n");
				sb.append("	var evt = new CustomEvent('ConfigureSecProxy',{\"detail\":{\"url\":\"" + manifestUrl + "\"}});\n");
				sb.append(" document.dispatchEvent(evt);\n");
				sb.append("};\n");
				sb.append("var btn = document.getElementById('btn');\n");
				sb.append("btn.addEventListener('click',click,false);\n");
				sb.append("</script>\n");
				*/
				
				// TODO
				sb.append("<html>\n");
				sb.append("<head>\n");
				sb.append("<title>");
				sb.append(Constant.messages.getString("api.html.title"));
				sb.append("</title>\n");
				sb.append("</head>\n");
				sb.append("<body>\n");

				sb.append(Constant.messages.getString("api.home.topmsg"));
				
				sb.append("<b>Note: This is a temporary add-on for testing MITM configuration :) </b><br>");

				sb.append("  <div id=\"messages\">\n");
				sb.append("    <div id=\"setup\" style=\"display:none\">\n");
				sb.append("      <p>Your browser does not seem to support automatic man-in-the-middle configuration</p>\n");
				sb.append("      <p>If you are using a recent version of Firefox, you can install the get the addon here:\n");
				sb.append("<b><a href=\"" + firefoxAddonUrl + "\">" + firefoxAddonUrl + "</a> </b></p>");
				sb.append("    </div>\n");
				sb.append("    <div id=\"in_progress\" style=\"display:none\">\n");
				sb.append("      <p>Configuring your browser to work with your man-in-the-middle proxy...</p>\n");
				sb.append("    </div>\n");
				sb.append("    <div id=\"success\" style=\"display:none\">\n");
				sb.append("      <p>Configuration succeeded!</p>\n");
				sb.append("    </div>\n");
				sb.append("    <div id=\"failure\" style=\"display:none\">\n");
				sb.append("      <p>Configuration failed</p>\n");
				sb.append("    </div>\n");
				sb.append("    <div id=\"activated\" style=\"display:none\">\n");
				sb.append("      <p>mitm support has been activated in your browser:</p>\n");
				sb.append("    </div>\n");
				sb.append("    <div id=\"actions\">\n");
				sb.append("      <p>\n");
				sb.append("      <button id=\"btn\">Click to setup!</button>\n");
				sb.append("      </p>\n");
				sb.append("  </div>\n");
				// TODO

				sb.append("</body>\n");
				sb.append("<script>\n");
				sb.append("  var detected = false;\n");
				sb.append("  var divs = ['setup','in_progress','success','failure','activated','actions'];\n");
				sb.append("  var manifest = {\"detail\":{\"url\":\"" + manifestUrl + "\"}};\n");

				sb.append("  // only show UI for the named elements\n");
				sb.append("  var showUI = function(visible){\n");
				sb.append("    for(var idx in divs){\n");
				sb.append("      if (-1 != visible.indexOf(divs[idx])) {\n");
				sb.append("        document.getElementById(divs[idx]).style.display = 'inline';\n");
				sb.append("        } else {\n");
				sb.append("        document.getElementById(divs[idx]).style.display = 'none';\n");
				sb.append("      }\n");
				sb.append("    }\n");
				sb.append("  };\n");

				sb.append("  // event listener for button press\n");
				sb.append("  var click = function(event) {\n");
				sb.append("    var evt = new CustomEvent('ConfigureSecProxy', manifest);\n");
				sb.append("    document.dispatchEvent(evt);\n");
				sb.append("    setTimeout(function() {\n");
				sb.append("      if (!detected) {\n");
				sb.append("        showUI(['setup']);\n");
				sb.append("     }\n");
				sb.append("    },1000);\n");
				sb.append("  };\n");

				sb.append("  // event listener for configuration started event\n");
				sb.append("  var started = function(event) {\n");
				sb.append("    console.log('configuration has started');\n");
				sb.append("    showUI(['in_progress']);\n");
				sb.append("    detected = true;\n");
				sb.append("  };\n");

				sb.append("  // event listener for configuration failed event\n");
				sb.append("  // use this to let the user know something has gone wrong\n");
				sb.append("  var failed = function(event) {\n");
				sb.append("    console.log('configuration has failed');\n");
				sb.append("    showUI(['failure','actions']);\n");
				sb.append("  };\n");

				sb.append("  // event listener for configuration succeeded\n");
				sb.append("  // use this to show a success message to a user in your welcome doc\n");
				sb.append("  var succeeded = function(event) {\n");
				sb.append("    console.log('configuration has succeeded');\n");
				sb.append("    showUI(['success']);\n");
				sb.append("  };\n");

				sb.append("  // event listener for browser support activated\n");
				sb.append("  var activated = function(event) {\n");
				sb.append("    console.log('activation has occurred');\n");
				sb.append("    showUI(['activated','actions']);\n");
				sb.append("  };\n");

				sb.append("  // hook event listener into button\n");
				sb.append("  var btn = document.getElementById('btn');\n");
				sb.append("  btn.addEventListener('click',click,false);\n");

				sb.append("  // Hook configuration event listeners into the document\n");
				sb.append("  document.addEventListener('ConfigureSecProxyStarted',started,false);\n");
				sb.append("  document.addEventListener('ConfigureSecProxyFailed',failed,false);\n");
				sb.append("  document.addEventListener('ConfigureSecProxyActivated',activated,false);\n");
				sb.append("  document.addEventListener('ConfigureSecProxySucceeded',succeeded,false);\n");
				sb.append("</script>\n");
				sb.append("</html>\n");

				// TODO done
				
				String response = sb.toString();
				
				msg.setResponseHeader(
						"HTTP/1.1 200 OK\r\n" +
						"Pragma: no-cache\r\n" +
						"Cache-Control: no-cache\r\n" + 
						"Access-Control-Allow-Origin: *\r\n" + 
						"Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n" + 
						"Access-Control-Allow-Headers: ZAP-Header\r\n" + 
						"Content-Length: " + response.length() + 
						"\r\nContent-Type: text/html;");
				
		    	msg.setResponseBody(response);
		    	
			} catch (Exception e) {
				logger.error(e.getMessage(), e);
			}
			return msg;
			
		} else if (OTHER_MANIFEST.equals(name)) {
			try {
				StringBuilder sb = new StringBuilder();
				sb.append("{\"mitmTool\":\"");
				sb.append(Constant.PROGRAM_NAME + " " + Constant.PROGRAM_VERSION);
				sb.append("\",\n");
				sb.append("\"proxyPAC\":\"" + root + PROXY_PAC + "\",\n");
				sb.append("\"protocolVersion\":\"1.00\",\n");
				sb.append("\"features\":{\n");
				sb.append("\"intercept\":\"true\",");
				sb.append("\"record\":\"true\",");
				sb.append("\"CACert\":\"" + root + ROOT_CERT + "\"}}\n");
				
				String response = sb.toString();
				
				msg.setResponseHeader(
						"HTTP/1.1 200 OK\r\n" +
						"Pragma: no-cache\r\n" +
						"Cache-Control: no-cache\r\n" + 
						"Access-Control-Allow-Origin: *\r\n" + 
						"Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n" + 
						"Access-Control-Allow-Headers: ZAP-Header\r\n" + 
						"Content-Length: " + response.length() + 
						"\r\nContent-Type: application/json");
				
		    	msg.setResponseBody(response);
		    	
			} catch (Exception e) {
				logger.error(e.getMessage(), e);
			}
			return msg;
			
		} else if (OTHER_FIREFOX_ADDON.equals(name)) {
			InputStream in = null;
			try {
				in = this.getClass().getResourceAsStream("resource/gclimitm.xpi");

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

	public static void main (String [] params) throws NoSuchAlgorithmException {
		MessageDigest cript = MessageDigest.getInstance("SHA-1");
        cript.reset();
        cript.update("sss".getBytes());
        String str = String.valueOf(Hex.encodeHex(cript.digest()));
        System.out.println("Str is " + str);
	}

}
