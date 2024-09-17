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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;

/**
 * Attempts to retrieve cloud metadata by forging the host header and requesting a specific URL. See
 * https://www.nginx.com/blog/trust-no-one-perils-of-trusting-user-input/ for more details
 */
public class CloudMetadataScanRule extends AbstractHostPlugin implements CommonActiveScanRuleInfo {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanrules.cloudmetadata.";

    private static final int PLUGIN_ID = 90034;
    private static final Logger LOGGER = LogManager.getLogger(CloudMetadataScanRule.class);
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG);

    // this class hold metadata endpoint details
    private static class CloudMetadataEndpoint {
        String host;
        String path;
        String provider;
        Map<String, String> headers;

        CloudMetadataEndpoint(
                String host, String path, String provider, Map<String, String> headers) {
            this.host = host;
            this.path = path;
            this.provider = provider;
            this.headers = headers;
        }
    }

    // metadata endpoints to test
    private static final List<CloudMetadataEndpoint> METADATA_ENDPOINTS =
            Arrays.asList(
                    // AWS
                    new CloudMetadataEndpoint(
                            "169.254.169.254", "/latest/meta-data/", "AWS", Collections.emptyMap()),
                    new CloudMetadataEndpoint(
                            "aws.zaproxy.org", "/latest/meta-data/", "AWS", Collections.emptyMap()),
                    // GCP
                    new CloudMetadataEndpoint(
                            "169.254.169.254",
                            "/computeMetadata/v1/",
                            "GCP",
                            Map.of("Metadata-Flavor", "Google")),
                    new CloudMetadataEndpoint(
                            "metadata.google.internal",
                            "/computeMetadata/v1/",
                            "GCP",
                            Map.of("Metadata-Flavor", "Google")),
                    // OCI
                    new CloudMetadataEndpoint(
                            "169.254.169.254", "/opc/v1/instance/", "OCI", Collections.emptyMap()),
                    new CloudMetadataEndpoint(
                            "metadata.oraclecloud.com",
                            "/opc/v1/instance/",
                            "OCI",
                            Collections.emptyMap()),
                    // Alibaba Cloud
                    new CloudMetadataEndpoint(
                            "100.100.100.200",
                            "/latest/meta-data/",
                            "AlibabaCloud",
                            Collections.emptyMap()),
                    new CloudMetadataEndpoint(
                            "alibaba.zaproxy.org",
                            "/latest/meta-data/",
                            "AlibabaCloud",
                            Collections.emptyMap()),
                    // Azure
                    new CloudMetadataEndpoint(
                            "169.254.169.254",
                            "/metadata/instance",
                            "Azure",
                            Map.of("Metadata", "true")));

    // metadata indicators for each cloud provider
    private static final Map<String, List<String>> PROVIDER_INDICATORS =
            Map.of(
                    "AWS",
                            Arrays.asList(
                                    "ami-id", "instance-id", "local-hostname", "public-hostname"),
                    "GCP", Arrays.asList("project-id", "zone", "machineType", "hostname"),
                    "Azure", Arrays.asList("compute", "network", "osType", "vmSize"),
                    "AlibabaCloud",
                            Arrays.asList("image-id", "instance-id", "hostname", "region-id"),
                    "OCI", Arrays.asList("oci", "instance", "availabilityDomain", "region"));

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
        for (CloudMetadataEndpoint endpoint : METADATA_ENDPOINTS) {
            HttpMessage newRequest = getNewMsg();
            try {
                // set the request path
                newRequest.getRequestHeader().getURI().setPath(endpoint.path);
                // set the Host header
                newRequest.setUserObject(Collections.singletonMap("host", endpoint.host));
                // set additional headers if required
                for (Map.Entry<String, String> header : endpoint.headers.entrySet()) {
                    newRequest.getRequestHeader().setHeader(header.getKey(), header.getValue());
                }
                sendAndReceive(newRequest, false);
                if (isSuccess(newRequest) && newRequest.getResponseBody().length() > 0) {
                    String responseBody = newRequest.getResponseBody().toString();
                    if (containsMetadataIndicators(responseBody, endpoint.provider)) {
                        this.createAlert(newRequest, endpoint.host).raise();
                        return;
                    }
                }
            } catch (Exception e) {
                LOGGER.warn("Error sending request to {}: {}", endpoint.host, e.getMessage(), e);
            }
        }
    }

    /**
     * Checks if the response body contains metadata indicators specific to the cloud provider.
     *
     * @param responseBody the response body to check
     * @param provider the cloud provider
     * @return {@code true} if cloud metadata indicators are found; {@code false} otherwise
     */
    private boolean containsMetadataIndicators(String responseBody, String provider) {
        List<String> indicators = PROVIDER_INDICATORS.get(provider);
        if (indicators == null) {
            return false;
        }
        for (String indicator : indicators) {
            if (responseBody.contains(indicator)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(createAlert(null, "www.example.com").build());
    }
}
