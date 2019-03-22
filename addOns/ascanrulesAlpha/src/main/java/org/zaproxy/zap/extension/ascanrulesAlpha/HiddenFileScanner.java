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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.io.IOException;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;


public class HiddenFileScanner extends AbstractHostPlugin {

    private static final String MESSAGE_PREFIX = "ascanalpha.hiddenfilescanner.";
    private static final int PLUGIN_ID = 40035;
    private static final String FILE_PATH = "json/config.json";
    private static final Logger LOG = Logger.getLogger(HiddenFileScanner.class);

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }


    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return null;
    }

    @Override
    public String[] getDependency() {
        return null;
    }

    @Override
    public int getCategory() {
        return Category.MISC;
    }


    private String generatePath(String baseUriPath, String hiddenFile) {
        String newPath = "";
        if (baseUriPath.contains("/")) {
            if (baseUriPath.endsWith("/")) {
                newPath = baseUriPath + hiddenFile;
            } else {
                newPath = baseUriPath.substring(0, baseUriPath.lastIndexOf('/')) + "/" + hiddenFile;
            }
        } else {
            newPath = baseUriPath + "/" + hiddenFile;
        }
        return newPath;
    }

    @Override
    public void scan() {

        String[] hiddenFilesToScan = readFromJSONfile();

        for(String hiddenFile: hiddenFilesToScan)
        {
            if (isStop()) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Scanner " + getName() + " Stopping.");
                }
                return;
            }
            HttpMessage newRequest = getNewMsg();
            newRequest.getRequestHeader().setMethod(HttpRequestHeader.GET);
            URI baseUri = getBaseMsg().getRequestHeader().getURI();
            URI pathUri = null;
            try {
                String baseUriPath = baseUri.getPath() == null ? "" : baseUri.getPath();
                pathUri = new URI(baseUri.getScheme(), null, baseUri.getHost(), baseUri.getPort(), generatePath(baseUriPath,hiddenFile));
            } catch (URIException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("An error occurred creating a URI for the: " + getName() + " scanner. " + e.getMessage(),
                            e);
                }
                return;
            }

            try {
                newRequest.getRequestHeader().setURI(pathUri);
            } catch (URIException uEx) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("An error occurred setting the URI for a new request used by: " + getName() + " scanner. "
                            + uEx.getMessage(), uEx);
                }
                return;
            }
            try {
                sendAndReceive(newRequest, false);
            } catch (IOException e) {
                LOG.warn("An error occurred while checking [" + newRequest.getRequestHeader().getMethod() + "] ["
                        + newRequest.getRequestHeader().getURI() + "] for " + getName() + " Caught "
                        + e.getClass().getName() + " " + e.getMessage());
                return;
            }

            int statusCode = newRequest.getResponseHeader().getStatusCode();
            if (statusCode == HttpStatusCode.OK) {
                raiseAlert(newRequest, getRisk(),"");
            } else if (statusCode == HttpStatusCode.UNAUTHORIZED || statusCode == HttpStatusCode.FORBIDDEN) {
                raiseAlert(newRequest, Alert.RISK_INFO, "Access to resource is forbidden.");
            }
        }
    }
    private String[] readFromJSONfile() {

        String jsonTxt = openFile();
        JSONObject json = (JSONObject) JSONSerializer.toJSON( jsonTxt );
        JSONArray files = json.getJSONArray("files");
        String[] hiddenFiles = new String[files.size()];
        for(int i=0; i<files.size(); i++)
        {
            hiddenFiles[i] = files.getJSONObject(i).getString("name");
            LOG.debug("File to be searched: " + hiddenFiles[i]);
        }

        return hiddenFiles;
    }

    private String openFile() {
        StringBuilder sb =  new StringBuilder();
        BufferedReader reader = null;
        File f = new File(Constant.getZapHome() + File.separator + FILE_PATH);
        if (! f.exists()) {
            LOG.error("No such file: " + f.getAbsolutePath());
            return sb.toString();
        }
        try {
            String line;
            reader = new BufferedReader(new FileReader(f));
            while ((line = reader.readLine()) != null) {
                if (line.length() > 0) {
                    sb.append(line);
                }
            }
        } catch (IOException e) {
            LOG.error("Error on opening/reading example error file. Error: " + e.getMessage(), e);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    LOG.debug("Error on closing the file reader. Error: " + e.getMessage(), e);
                }
            }
        }
        return sb.toString();
    }

    private void raiseAlert(HttpMessage msg, int risk, String otherInfo) {
        bingo(risk, // Risk
                Alert.CONFIDENCE_HIGH, // Confidence
                getName(), // Name
                getDescription(), // Description
                msg.getRequestHeader().getURI().toString(), // URI
                null, // Param
                "", // Attack
                otherInfo, // OtherInfo
                getSolution(), // Solution
                msg.getResponseHeader().getPrimeHeader(), // Evidence
                getCweId(), // CWE ID
                getWascId(), // WASC ID
                msg); // HTTPMessage
    }

}
