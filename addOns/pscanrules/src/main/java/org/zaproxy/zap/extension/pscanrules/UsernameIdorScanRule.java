/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrules;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.users.User;

public class UsernameIdorScanRule extends PluginPassiveScanner {

    private static final String MESSAGE_PREFIX = "pscanrules.usernameidor.";
    private static final int PLUGIN_ID = 10057;

    private static final Logger LOGGER = Logger.getLogger(UsernameIdorScanRule.class);

    private static final String ADMIN = "Admin";
    private static final String ADMIN_2 = "admin";

    public static final List<String> DEFAULT_USERNAMES = Arrays.asList(ADMIN, ADMIN_2);
    private static final Supplier<Iterable<String>> DEFAULT_PAYLOAD_PROVIDER =
            () -> DEFAULT_USERNAMES;
    public static final String USERNAME_IDOR_PAYLOAD_CATEGORY = "Username-Idor";

    private static Supplier<Iterable<String>> payloadProvider = DEFAULT_PAYLOAD_PROVIDER;

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    private List<User> getUsers() {
        List<User> usersList = new ArrayList<>();

        for (String payload : getUsernameIdorPayloads().get()) {
            usersList.add(new User(-1, payload));
        }

        usersList.addAll(getHelper().getUsers());
        return usersList;
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // Only checking the response for this plugin
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        List<User> scanUsers = getUsers();
        if (scanUsers.isEmpty()) { // Should continue if not empty
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("There does not appear to be any contexts with configured users.");
            }
            return;
        }

        long start = System.currentTimeMillis();

        String response = msg.getResponseHeader().toString() + msg.getResponseBody().toString();
        String username;

        for (User user : scanUsers) {
            username = user.getName();
            Map<String, String> hashes = new HashMap<String, String>();
            hashes.put("MD2", DigestUtils.md2Hex(username));
            hashes.put("MD5", DigestUtils.md5Hex(username));
            hashes.put("SHA1", DigestUtils.sha1Hex(username));
            hashes.put("SHA256", DigestUtils.sha256Hex(username));
            hashes.put("SHA384", DigestUtils.sha384Hex(username));
            hashes.put("SHA512", DigestUtils.sha512Hex(username));
            for (Map.Entry<String, String> entry : hashes.entrySet()) {
                String hash = entry.getValue();
                String evidence = match(response, Pattern.compile(hash, Pattern.CASE_INSENSITIVE));
                if (evidence != null) {
                    this.raiseAlert(username, evidence, entry.getKey(), id, msg);
                }
            }
        }
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(
                    "\tScan of record "
                            + id
                            + " took "
                            + (System.currentTimeMillis() - start)
                            + " ms");
        }
    }

    private void raiseAlert(
            String username, String evidence, String hashType, int id, HttpMessage msg) {
        newAlert()
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setDescription(getDescription(username))
                .setOtherInfo(getOtherinfo(hashType, evidence))
                .setSolution(getSolution())
                .setReference(getReference())
                .setEvidence(evidence)
                // CWE-284: Improper Access Control
                .setCweId(284)
                // WASC-02: Insufficient Authorization
                .setWascId(02)
                .raise();
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    private String getDescription(String username) {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc", username);
    }

    private String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    private String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    private String getOtherinfo(String hashType, String hashValue) {
        return Constant.messages.getString(MESSAGE_PREFIX + "otherinfo", hashType, hashValue);
    }

    public String match(String contents, Pattern pattern) {
        Matcher matcher = pattern.matcher(contents);
        if (matcher.find()) {
            return matcher.group();
        }
        return null;
    }

    public static void setPayloadProvider(Supplier<Iterable<String>> provider) {
        payloadProvider = provider == null ? DEFAULT_PAYLOAD_PROVIDER : provider;
    }

    private static Supplier<Iterable<String>> getUsernameIdorPayloads() {
        return payloadProvider;
    }
}
