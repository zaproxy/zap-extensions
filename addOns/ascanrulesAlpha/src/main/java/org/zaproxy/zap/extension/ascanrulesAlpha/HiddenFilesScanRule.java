/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;
import net.sf.json.JSONArray;
import net.sf.json.JSONException;
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
import org.parosproxy.paros.network.HttpStatusCode;

/**
 * Active scan rule which checks whether various URL paths are exposed.
 * https://github.com/zaproxy/zaproxy/issues/4585
 *
 * <p>Initial payload set adapted from snallygaster (by Hanno Böck):
 * https://github.com/hannob/snallygaster
 *
 * <p><strong>Note:</strong> Binary matching assumes:<br>
 * - Start position 0 (ex: checking magic numbers) [startsWith, not contains]<br>
 * - Response is ASCII compatible (which should include UTF-8 and ISO-8859-1)
 *
 * @author kingthorin+owaspzap@gmail.com
 */
public class HiddenFilesScanRule extends AbstractHostPlugin {

    private static final String MESSAGE_PREFIX = "ascanalpha.hidden.files.";
    private static final int PLUGIN_ID = 40035;
    private static final Logger LOG = Logger.getLogger(HiddenFilesScanRule.class);

    private static final String PAYLOADS_FILE_PATH = "json/hidden_files.json";

    public static final List<String> HIDDEN_FILES = new ArrayList<>();
    private static final Supplier<Iterable<String>> DEFAULT_PAYLOAD_PROVIDER = () -> HIDDEN_FILES;
    public static final String HIDDEN_FILE_PAYLOAD_CATEGORY = "Hidden-File";
    private static Supplier<Iterable<String>> payloadProvider = DEFAULT_PAYLOAD_PROVIDER;

    private static List<HiddenFile> hfList = Collections.emptyList();

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public void init() {
        hfList = readFromJsonFile();
        for (String payload : getHiddenFilePayloads().get()) {
            hfList.add(
                    new HiddenFile(
                            payload,
                            Collections.emptyList(),
                            Collections.emptyList(),
                            "",
                            Collections.emptyList(),
                            ""));
        }
    }

    @Override
    public void scan() {
        for (HiddenFile file : hfList) {

            if (isStop()) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Scan rule " + getName() + " stopping.");
                }
                return;
            }

            HttpMessage testMsg = sendHiddenFileRequest(file);
            if (testMsg == null) {
                continue;
            }
            int statusCode = testMsg.getResponseHeader().getStatusCode();
            if (statusCode == HttpStatusCode.OK) {
                String responseBody = testMsg.getResponseBody().toString();
                // If all the content checks matched then confidence is high
                boolean matches =
                        doesNotMatch(responseBody, file.getNotContent())
                                && doesMatch(responseBody, file.getContent())
                                && doesBinaryMatch(responseBody, file.getBinary());
                raiseAlert(
                        testMsg,
                        matches ? Alert.CONFIDENCE_HIGH : Alert.CONFIDENCE_LOW,
                        getRisk(),
                        file);
            } else if (statusCode == HttpStatusCode.UNAUTHORIZED
                    || statusCode == HttpStatusCode.FORBIDDEN) {
                raiseAlert(testMsg, Alert.CONFIDENCE_LOW, Alert.RISK_INFO, file);
            }
        }
    }

    private static String generatePath(String baseUriPath, String hiddenFile) {
        String newPath = "";
        if (baseUriPath == null) {
            newPath = "/" + hiddenFile;
        } else if (baseUriPath.contains("/")) {
            if (baseUriPath.endsWith("/")) {
                newPath = baseUriPath + hiddenFile;
            } else {
                newPath = baseUriPath.substring(0, baseUriPath.indexOf('/')) + "/" + hiddenFile;
            }
        } else {
            newPath = baseUriPath + "/" + hiddenFile;
        }
        return newPath;
    }

    private HttpMessage sendHiddenFileRequest(HiddenFile file) {
        HttpMessage testMsg = getNewMsg();
        try {
            URI baseUri = getBaseMsg().getRequestHeader().getURI();
            URI testUri =
                    new URI(
                            baseUri.getScheme(),
                            null,
                            baseUri.getHost(),
                            baseUri.getPort(),
                            generatePath(baseUri.getPath(), file.getPath()));
            testMsg.getRequestHeader().setURI(testUri);
            sendAndReceive(testMsg);
            return testMsg;
        } catch (URIException uEx) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(
                        "An error occurred creating or setting a URI for the: "
                                + getName()
                                + " scan rule. "
                                + uEx.getMessage(),
                        uEx);
            }
        } catch (IOException e) {
            LOG.warn(
                    "An error occurred while checking ["
                            + testMsg.getRequestHeader().getMethod()
                            + "] ["
                            + testMsg.getRequestHeader().getURI()
                            + "] for "
                            + getName()
                            + " Caught "
                            + e.getClass().getName()
                            + " "
                            + e.getMessage());
        }
        return null;
    }

    private void raiseAlert(HttpMessage msg, int confidence, int risk, HiddenFile file) {
        newAlert()
                .setRisk(risk)
                .setConfidence(confidence)
                .setName(getAlertName())
                .setOtherInfo(getOtherInfo(file.getType()))
                .setEvidence(msg.getResponseHeader().getPrimeHeader())
                .setReference(getReferences(file))
                .setMessage(msg)
                .raise();
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public int getCategory() {
        return Category.INFO_GATHER;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    @Override
    public int getCweId() {
        return 538; // CWE-538: File and Directory Information Exposure
    }

    @Override
    public int getWascId() {
        return 13; // WASC-13: Information Leakage
    }

    private String getReferences(HiddenFile file) {
        String refs = getReference();
        for (String ref : file.getLinks()) {
            refs = !ref.isEmpty() ? refs + "\n" + ref : "";
        }
        return refs;
    }

    private static String getAlertName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "alert.name");
    }

    private static String getOtherInfo(String type) {
        return Constant.messages.getString(MESSAGE_PREFIX + "otherinfo", type);
    }

    private List<HiddenFile> readFromJsonFile() {
        String jsonTxt = readPayloadsFile();
        if (jsonTxt.isEmpty()) {
            return new ArrayList<>();
        }
        try {
            JSONObject json = (JSONObject) JSONSerializer.toJSON(jsonTxt);
            JSONArray files = json.getJSONArray("files");
            List<HiddenFile> hiddenFiles = new ArrayList<>();

            for (int i = 0; i < files.size(); i++) {
                JSONObject hiddenFileObject = files.getJSONObject(i);
                HiddenFile hiddenFile =
                        new HiddenFile(
                                hiddenFileObject.getString("path"),
                                getOptionalList(hiddenFileObject, "content"),
                                getOptionalList(hiddenFileObject, "not_content"),
                                getOptionalString(hiddenFileObject, "binary"),
                                getOptionalList(hiddenFileObject, "links"),
                                getOptionalString(hiddenFileObject, "type"));
                hiddenFiles.add(hiddenFile);

                if (LOG.isDebugEnabled()) {
                    LOG.debug(
                            "File to be located: "
                                    + hiddenFile.getPath()
                                    + " Content: "
                                    + hiddenFile.getContent());
                }
            }

            return hiddenFiles;
        } catch (JSONException jEx) {
            LOG.warn(
                    "Failed to parse "
                            + getName()
                            + " payloads file due to JSON parsing issue. "
                            + jEx.getMessage(),
                    jEx);
            return new ArrayList<>();
        }
    }

    private static String getOptionalString(JSONObject jsonObj, String key) {
        if (!jsonObj.has(key)) {
            return "";
        }
        try {
            return jsonObj.getString(key);
        } catch (JSONException jEx) {
            LOG.warn("Unable to parse JSON (" + key + ").", jEx);
            return "";
        }
    }

    private static List<String> getOptionalList(JSONObject jsonObj, String key) {
        if (!jsonObj.has(key)) {
            return Collections.emptyList();
        }
        JSONArray jsonArray;
        try {
            jsonArray = jsonObj.getJSONArray(key);
        } catch (JSONException jEx) {
            LOG.warn("Unable to parse JSON (" + key + ").", jEx);
            return Collections.emptyList();
        }
        List<String> newList = new ArrayList<>();
        for (int x = 0; x < jsonArray.size(); x++) {
            newList.add(jsonArray.getString(x));
        }
        return newList;
    }

    private String readPayloadsFile() {
        File f = new File(Constant.getZapHome() + File.separator + PAYLOADS_FILE_PATH);
        if (!f.exists()) {
            LOG.error("No such file: " + f.getAbsolutePath());
            return "";
        }
        try {
            return new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
        } catch (IOException e) {
            LOG.error(
                    "Error on opening/reading "
                            + getName()
                            + " payload file. Error: "
                            + e.getMessage(),
                    e);
        }
        return "";
    }

    private static boolean doesMatch(String responseBody, List<String> testStrings) {
        if (testStrings.isEmpty()) {
            return true;
        }
        for (String testStr : testStrings) {
            if (!responseBody.contains(testStr)) {
                // If one of the content checks fails no need to loop further
                return false;
            }
        }
        return true;
    }

    private static boolean doesNotMatch(String responseBody, List<String> notContentStrings) {
        if (notContentStrings.isEmpty()) {
            return true;
        }
        return !doesMatch(responseBody, notContentStrings);
    }

    private static boolean doesBinaryMatch(String responseBody, String binary) {
        return responseBody.startsWith(HexString.compile(binary));
    }

    public static void setPayloadProvider(Supplier<Iterable<String>> provider) {
        payloadProvider = provider == null ? DEFAULT_PAYLOAD_PROVIDER : provider;
    }

    private static Supplier<Iterable<String>> getHiddenFilePayloads() {
        return payloadProvider;
    }

    /**
     * For UnitTest purposes. Must be executed after {@link #init()}
     *
     * @param payload the {@code HiddenFile} payload to be added.
     */
    static void addTestPayload(HiddenFile payload) {
        hfList.add(payload);
    }

    static class HiddenFile {
        private final String path;
        private final List<String> content;
        private final List<String> not_content;
        private final String binary;
        private final List<String> links;
        private final String type;

        public HiddenFile(
                String path,
                List<String> content,
                List<String> not_content,
                String binary,
                List<String> links,
                String type) {
            super();
            this.path = path;
            this.content = content;
            this.not_content = not_content;
            this.binary = binary;
            this.links = links;
            this.type = type;
        }

        public String getPath() {
            return path;
        }

        public List<String> getContent() {
            return content;
        }

        public List<String> getNotContent() {
            return not_content;
        }

        public String getBinary() {
            return binary;
        }

        public List<String> getLinks() {
            return links;
        }

        public String getType() {
            return type;
        }
    }
}
