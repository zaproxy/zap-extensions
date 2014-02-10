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
package org.zaproxy.zap.extension.plugnhack;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;

import net.sf.json.JSON;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiOther;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;

public class PlugNHackAPI extends ApiImplementor {

    private static Logger logger = Logger.getLogger(PlugNHackAPI.class);
    private static final String PREFIX = "pnh";
    private static final String ACTION_MONITOR = "monitor";
    private static final String ACTION_ORACLE = "oracle";
    private static final String ACTION_START_MONITORING = "startMonitoring";
    private static final String ACTION_STOP_MONITORING = "stopMonitoring";
    // TODO API calls for managing the monitoring regexes?  
    // private static final String ACTION_ADD_MONITORING_REGEX = "stopMonitoring";
    private static final String OTHER_PNH = "pnh";
    private static final String OTHER_MANIFEST = "manifest";
    private static final String OTHER_SERVICE = "service";
    private static final String OTHER_FIREFOX_ADDON = "fx_pnh.xpi";
    private static final String PARAM_ID = "id";
    private static final String PARAM_MESSAGE = "message";
    private static final String PARAM_URL = "url";
    private ExtensionPlugNHack extension = null;

    /**
     * 
     * @param ext 
     */
    public PlugNHackAPI(ExtensionPlugNHack ext) {

        extension = ext;

        this.addApiAction(new ApiAction(ACTION_MONITOR, new String[]{PARAM_ID, PARAM_MESSAGE}));
        this.addApiAction(new ApiAction(ACTION_ORACLE, new String[]{PARAM_ID}));
        this.addApiAction(new ApiAction(ACTION_START_MONITORING, new String[]{PARAM_URL}));
        this.addApiAction(new ApiAction(ACTION_STOP_MONITORING, new String[]{PARAM_ID}));

        this.addApiOthers(new ApiOther(OTHER_PNH, false));
        this.addApiOthers(new ApiOther(OTHER_MANIFEST, false));
        this.addApiOthers(new ApiOther(OTHER_SERVICE, false));
        this.addApiOthers(new ApiOther(OTHER_FIREFOX_ADDON, false));

        this.addApiShortcut(OTHER_PNH);
        this.addApiShortcut(OTHER_MANIFEST);
    }

    /**
     * 
     * @return 
     */
    @Override
    public String getPrefix() {
        return PREFIX;
    }

    /**
     * 
     * @param name
     * @param params
     * @return
     * @throws ApiException 
     */
    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        ApiResponse response = ApiResponseElement.OK;

        if (ACTION_MONITOR.equals(name)) {
            String id = params.getString(PARAM_ID);
            String message = params.getString(PARAM_MESSAGE);

            JSONObject json = JSONObject.fromObject(message);

            ApiResponse resp = this.extension.messageReceived(new ClientMessage(id, json));
            if (response != null) {
                // logger.debug("Returning " + response.toString(0));
                response = resp;
            }
            
        } else if (ACTION_ORACLE.equals(name)) {
            extension.oracleInvoked(params.getInt(PARAM_ID));

        } else if (ACTION_START_MONITORING.equals(name)) {
            String url = params.getString(PARAM_URL);
            try {
                String id = this.extension.startMonitoring(new URI(url, true));
                response = new ApiResponseElement(PARAM_ID, id);

            } catch (Exception e) {
                throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, e.getMessage());
            }
            
        } else if (ACTION_STOP_MONITORING.equals(name)) {
            String id = params.getString(PARAM_ID);
            this.extension.stopMonitoring(id);
        }

        return response;
    }

    /**
     * 
     * @param msg
     * @param name
     * @param params
     * @return
     * @throws ApiException 
     */
    @Override
    public HttpMessage handleApiOther(HttpMessage msg, String name, JSONObject params) throws ApiException {
        String root = this.extension.getApiRoot();

        if (OTHER_PNH.equals(name)) {
            try {
                String welcomePage = ExtensionPlugNHack.getStringReource("resource/welcome.html");
                // Replace the dynamic parts
                welcomePage = welcomePage.replace("{{ROOT}}", root).replace("{{APIKEY}}", API.getInstance().getApiKey());
                // Replace the i18n strings
                welcomePage = welcomePage.replace("{{MSG.TITLE}}", Constant.messages.getString("plugnhack.title"));
                welcomePage = welcomePage.replace("{{MSG.HEADER}}", Constant.messages.getString("plugnhack.header"));
                welcomePage = welcomePage.replace("{{MSG.INTRO1}}", Constant.messages.getString("plugnhack.intro1"));
                welcomePage = welcomePage.replace("{{MSG.INTRO2}}", Constant.messages.getString("plugnhack.intro2"));
                welcomePage = welcomePage.replace("{{MSG.SETUP1}}", Constant.messages.getString("plugnhack.setup1"));
                welcomePage = welcomePage.replace("{{MSG.SETUP2}}", Constant.messages.getString("plugnhack.setup2"));
                welcomePage = welcomePage.replace("{{MSG.PROGRESS}}", Constant.messages.getString("plugnhack.progress"));
                welcomePage = welcomePage.replace("{{MSG.FAILURE}}", Constant.messages.getString("plugnhack.failure"));
                welcomePage = welcomePage.replace("{{MSG.SUCCESS}}", Constant.messages.getString("plugnhack.success"));
                welcomePage = welcomePage.replace("{{MSG.ACTIVATED}}", Constant.messages.getString("plugnhack.activated"));
                welcomePage = welcomePage.replace("{{MSG.BUTTON}}", Constant.messages.getString("plugnhack.button"));
                welcomePage = welcomePage.replace("{{MSG.FIREFOX}}", Constant.messages.getString("plugnhack.firefox"));

                /*
                 // TODO - this seems to detect Firefox fine...
                 String userAgent = msg.getRequestHeader().getHeader(HttpHeader.USER_AGENT);
                 if (userAgent.toLowerCase().indexOf("firefox") >= 0) {
                 // It looks like firefox
                 }
                 */

                msg.setResponseHeader(
                        "HTTP/1.1 200 OK\r\n"
                        + "Pragma: no-cache\r\n"
                        + "Cache-Control: no-cache\r\n"
                        + "Access-Control-Allow-Origin: *\r\n"
                        + "Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n"
                        + "Access-Control-Allow-Headers: ZAP-Header\r\n"
                        + "Content-Length: " + welcomePage.length()
                        + "\r\nContent-Type: text/html;");

                msg.setResponseBody(welcomePage);

            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }
            
            return msg;

        } else if (OTHER_MANIFEST.equals(name)) {
            try {
                String manifest = ExtensionPlugNHack.getStringReource("resource/manifest.json");
                // Replace the dynamic parts
                manifest = manifest.replace("{{ROOT}}", root).replace("{{APIKEY}}", API.getInstance().getApiKey());

                msg.setResponseHeader(
                        "HTTP/1.1 200 OK\r\n"
                        + "Pragma: no-cache\r\n"
                        + "Cache-Control: no-cache\r\n"
                        + "Access-Control-Allow-Origin: *\r\n"
                        + "Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n"
                        + "Access-Control-Allow-Headers: ZAP-Header\r\n"
                        + "Content-Length: " + manifest.length()
                        + "\r\nContent-Type: application/json");

                msg.setResponseBody(manifest);

            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }
            
            return msg;

        } else if (OTHER_SERVICE.equals(name)) {
            try {
                String service = ExtensionPlugNHack.getStringReource("resource/service.json");
                // Replace the dynamic parts
                service = service.replace("{{ROOT}}", root).replace("{{APIKEY}}", API.getInstance().getApiKey());

                msg.setResponseHeader(
                        "HTTP/1.1 200 OK\r\n"
                        + "Pragma: no-cache\r\n"
                        + "Cache-Control: no-cache\r\n"
                        + "Access-Control-Allow-Origin: *\r\n"
                        + "Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n"
                        + "Access-Control-Allow-Headers: ZAP-Header\r\n"
                        + "Content-Length: " + service.length()
                        + "\r\nContent-Type: application/json");

                msg.setResponseBody(service);

            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }
            
            return msg;

        } else if (OTHER_FIREFOX_ADDON.equals(name)) {
            InputStream in = null;
            try {
                in = this.getClass().getResourceAsStream("resource/" + OTHER_FIREFOX_ADDON);

                int numRead = 0;
                int length = 0;
                byte[] buf = new byte[1024];
                while ((numRead = in.read(buf)) != -1) {
                    msg.getResponseBody().append(buf, numRead);
                    length += numRead;
                }

                msg.setResponseHeader(
                        "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: application/x-xpinstall"
                        + "Accept-Ranges: byte"
                        + "Pragma: no-cache\r\n"
                        + "Cache-Control: no-cache\r\n"
                        + "Access-Control-Allow-Origin: *\r\n"
                        + "Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n"
                        + "Access-Control-Allow-Headers: ZAP-Header\r\n"
                        + "Content-Length: " + length + "\r\n");

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
    public HttpMessage handleShortcut(HttpMessage msg) throws ApiException {
        try {
            if (msg.getRequestHeader().getURI().getPath().startsWith("/" + OTHER_PNH)) {
                return this.handleApiOther(msg, OTHER_PNH, null);
        
            } else if (msg.getRequestHeader().getURI().getPath().startsWith("/" + OTHER_MANIFEST)) {
                return this.handleApiOther(msg, OTHER_MANIFEST, null);
            }
            
        } catch (URIException e) {
            logger.error(e.getMessage(), e);
            throw new ApiException(ApiException.Type.INTERNAL_ERROR);
        }
        
        throw new ApiException(ApiException.Type.URL_NOT_FOUND, msg.getRequestHeader().getURI().toString());
    }

    /**
     * 
     * @param args
     * @throws Exception 
     */
    public static void main(String[] args) throws Exception {
        // Sanity check the json config files are valid!
        JSON json;

        String manifest = ExtensionPlugNHack.getStringReource("resource/manifest.json");
        //System.out.println("Manifest = " + manifest);
        json = JSONSerializer.toJSON(manifest);
        System.out.println("Manifest OK? " + json);

        String service = ExtensionPlugNHack.getStringReource("resource/service.json");
        //System.out.println("Service = " + service);
        json = JSONSerializer.toJSON(service);
        System.out.println("Service OK? " + json);

        // Calculate the Firefox addon hash

        InputStream in = null;
        try {
            in = ExtensionPlugNHack.class.getResourceAsStream("resource/" + OTHER_FIREFOX_ADDON);
            MessageDigest md = MessageDigest.getInstance("SHA1");
            //FileInputStream fis = new FileInputStream(in);
            byte[] dataBytes = new byte[1024];
            int nread = 0;

            while ((nread = in.read(dataBytes)) != -1) {
                md.update(dataBytes, 0, nread);
            }

            byte[] mdbytes = md.digest();

            //convert the byte to hex format
            StringBuilder sb = new StringBuilder("");
            for (int i = 0; i < mdbytes.length; i++) {
                sb.append(Integer.toString((mdbytes[i] & 0xff) + 0x100, 16).substring(1));
            }

            System.out.println("Digest(in hex format):: " + sb.toString());

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
}
