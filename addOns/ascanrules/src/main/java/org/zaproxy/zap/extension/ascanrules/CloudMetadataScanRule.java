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
package org.zaproxy.zap.extension.ascanrules;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;

/**
 * Attempts to retrieve cloud metadata by forging the host header and requesting a specific URL. See
 * https://www.nginx.com/blog/trust-no-one-perils-of-trusting-user-input/ for more details
 */
public class CloudMetadataScanRule extends AbstractHostPlugin implements CommonActiveScanRuleInfo {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanrules.cloudmetadata.";

    private static final int PLUGIN_ID = 90034;
    private static final Logger LOGGER = LogManager.getLogger(CloudMetadataScanRule.class);
    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                                CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG));
        alertTags.put(PolicyTag.API.getTag(), "");
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    private enum CloudProvider {
        AWS(
                List.of(
                        new Endpoint("169.254.169.254", "/latest/meta-data/", Map.of()),
                        new Endpoint("aws.zaproxy.org", "/latest/meta-data/", Map.of())),
                Set.of("ami-id", "instance-id", "local-hostname", "public-hostname")),
        GCP(
                List.of(
                        new Endpoint(
                                "169.254.169.254",
                                "/computeMetadata/v1/",
                                Map.of("Metadata-Flavor", "Google")),
                        new Endpoint(
                                "metadata.google.internal",
                                "/computeMetadata/v1/",
                                Map.of("Metadata-Flavor", "Google"))),
                Set.of("project-id", "zone", "machineType", "hostname")),
        OCI(
                List.of(
                        new Endpoint("169.254.169.254", "/opc/v1/instance/", Map.of()),
                        new Endpoint("metadata.oraclecloud.com", "/opc/v1/instance/", Map.of())),
                Set.of("oci", "instance", "availabilityDomain", "region")),
        ALIBABA_CLOUD(
                List.of(
                        new Endpoint("100.100.100.200", "/latest/meta-data/", Map.of()),
                        new Endpoint("alibaba.zaproxy.org", "/latest/meta-data/", Map.of())),
                Set.of("image-id", "instance-id", "hostname", "region-id")),
        AZURE(
                List.of(
                        new Endpoint(
                                "169.254.169.254",
                                "/metadata/instance",
                                Map.of("Metadata", "true"))),
                Set.of("compute", "network", "osType", "vmSize"));

        private final List<Endpoint> endpoints;
        private final Set<String> indicators;

        CloudProvider(List<Endpoint> endpoints, Set<String> indicators) {
            this.endpoints = endpoints;
            this.indicators = indicators;
        }

        public List<Endpoint> getEndpoints() {
            return endpoints;
        }

        public boolean containsMetadataIndicators(String responseBody) {
            for (String indicator : indicators) {
                if (responseBody.contains(indicator)) {
                    return true;
                }
            }
            return false;
        }

        private static class Endpoint {
            String host;
            String path;
            Map<String, String> headers;

            Endpoint(String host, String path, Map<String, String> headers) {
                this.host = host;
                this.path = path;
                this.headers = headers;
            }
        }
    }

    @Override
    public int getId() {
        return PLUGIN_ID;
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
        return Category.INJECTION;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    public AlertBuilder createAlert(HttpMessage newRequest, String host) {
        return newAlert()
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setAttack(host)
                .setOtherInfo(Constant.messages.getString(MESSAGE_PREFIX + "otherinfo"))
                .setMessage(newRequest);
    }

    @Override
    public void scan() {
        for (CloudProvider provider : CloudProvider.values()) {
            for (CloudProvider.Endpoint endpoint : provider.getEndpoints()) {
                HttpMessage newRequest = getNewMsg();
                try {
                    newRequest.getRequestHeader().getURI().setPath(endpoint.path);
                    newRequest.setUserObject(Collections.singletonMap("host", endpoint.host));
                    for (Map.Entry<String, String> header : endpoint.headers.entrySet()) {
                        newRequest.getRequestHeader().setHeader(header.getKey(), header.getValue());
                    }
                    sendAndReceive(newRequest, false);
                    if (isSuccess(newRequest) && newRequest.getResponseBody().length() > 0) {
                        String responseBody = newRequest.getResponseBody().toString();
                        if (provider.containsMetadataIndicators(responseBody)) {
                            this.createAlert(newRequest, endpoint.host).raise();
                            return;
                        }
                    }
                } catch (Exception e) {
                    LOGGER.warn(
                            "Error sending request to {}: {}", endpoint.host, e.getMessage(), e);
                }
            }
        }
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(createAlert(null, "www.example.com").build());
    }
}
