/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.network;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Arrays;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.internal.cert.CertificateUtils;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiOther;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiView;

public class NetworkApi extends ApiImplementor {

    private static final Logger LOGGER = LogManager.getLogger(NetworkApi.class);

    private static final String PREFIX = "network";

    private static final String ACTION_GENERATE_ROOT_CA_CERT = "generateRootCaCert";
    private static final String ACTION_IMPORT_ROOT_CA_CERT = "importRootCaCert";
    private static final String ACTION_SET_ROOT_CA_CERT_VALIDITY = "setRootCaCertValidity";
    private static final String ACTION_SET_SERVER_CERT_VALIDITY = "setServerCertValidity";

    private static final String VIEW_GET_ROOT_CA_CERT_VALIDITY = "getRootCaCertValidity";
    private static final String VIEW_GET_SERVER_CERT_VALIDITY = "getServerCertValidity";

    private static final String OTHER_ROOT_CA_CERT = "rootCaCert";

    private static final String PARAM_FILE_PATH = "filePath";
    private static final String PARAM_VALIDITY = "validity";

    private final ExtensionNetwork extensionNetwork;

    public NetworkApi() {
        this(null);
    }

    public NetworkApi(ExtensionNetwork extensionNetwork) {
        this.extensionNetwork = extensionNetwork;

        this.addApiAction(new ApiAction(ACTION_GENERATE_ROOT_CA_CERT));
        this.addApiAction(
                new ApiAction(ACTION_IMPORT_ROOT_CA_CERT, Arrays.asList(PARAM_FILE_PATH)));

        if (isHandleServerCerts(extensionNetwork)) {
            this.addApiAction(
                    new ApiAction(ACTION_SET_ROOT_CA_CERT_VALIDITY, Arrays.asList(PARAM_VALIDITY)));
            this.addApiAction(
                    new ApiAction(ACTION_SET_SERVER_CERT_VALIDITY, Arrays.asList(PARAM_VALIDITY)));

            this.addApiView(new ApiView(VIEW_GET_ROOT_CA_CERT_VALIDITY));
            this.addApiView(new ApiView(VIEW_GET_SERVER_CERT_VALIDITY));
        }

        this.addApiOthers(new ApiOther(OTHER_ROOT_CA_CERT, false));
    }

    private static boolean isHandleServerCerts(ExtensionNetwork extensionNetwork) {
        return extensionNetwork == null || extensionNetwork.isHandleServerCerts();
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        switch (name) {
            case ACTION_GENERATE_ROOT_CA_CERT:
                if (extensionNetwork.generateRootCaCert()) {
                    return ApiResponseElement.OK;
                }
                return ApiResponseElement.FAIL;

            case ACTION_IMPORT_ROOT_CA_CERT:
                Path file = Paths.get(params.getString(PARAM_FILE_PATH));
                String errorMessage = extensionNetwork.importRootCaCert(file);
                if (errorMessage == null) {
                    return ApiResponseElement.OK;
                }
                throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, errorMessage);

            case ACTION_SET_ROOT_CA_CERT_VALIDITY:
                if (!isHandleServerCerts(extensionNetwork)) {
                    throw new ApiException(ApiException.Type.BAD_ACTION);
                }

                try {
                    Duration validity = Duration.ofDays(params.getInt(PARAM_VALIDITY));
                    extensionNetwork.getServerCertificatesOptions().setRootCaCertValidity(validity);
                    return ApiResponseElement.OK;
                } catch (Exception e) {
                    throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, PARAM_VALIDITY);
                }

            case ACTION_SET_SERVER_CERT_VALIDITY:
                if (!isHandleServerCerts(extensionNetwork)) {
                    throw new ApiException(ApiException.Type.BAD_ACTION);
                }

                try {
                    Duration validity = Duration.ofDays(params.getInt(PARAM_VALIDITY));
                    extensionNetwork.getServerCertificatesOptions().setServerCertValidity(validity);
                    return ApiResponseElement.OK;
                } catch (Exception e) {
                    throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, PARAM_VALIDITY);
                }

            default:
                throw new ApiException(ApiException.Type.BAD_ACTION);
        }
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        switch (name) {
            case VIEW_GET_ROOT_CA_CERT_VALIDITY:
                if (!isHandleServerCerts(extensionNetwork)) {
                    throw new ApiException(ApiException.Type.BAD_VIEW);
                }

                return new ApiResponseElement(
                        name,
                        String.valueOf(
                                extensionNetwork
                                        .getServerCertificatesOptions()
                                        .getRootCaCertValidity()
                                        .toDays()));

            case VIEW_GET_SERVER_CERT_VALIDITY:
                if (!isHandleServerCerts(extensionNetwork)) {
                    throw new ApiException(ApiException.Type.BAD_VIEW);
                }

                return new ApiResponseElement(
                        name,
                        String.valueOf(
                                extensionNetwork
                                        .getServerCertificatesOptions()
                                        .getServerCertValidity()
                                        .toDays()));

            default:
                throw new ApiException(ApiException.Type.BAD_VIEW);
        }
    }

    @Override
    public HttpMessage handleApiOther(HttpMessage msg, String name, JSONObject params)
            throws ApiException {
        switch (name) {
            case OTHER_ROOT_CA_CERT:
                KeyStore keyStore = extensionNetwork.getRootCaKeyStore();
                if (keyStore == null) {
                    throw new ApiException(ApiException.Type.DOES_NOT_EXIST);
                }

                String pem = CertificateUtils.keyStoreToCertificatePem(keyStore);
                if (pem.isEmpty()) {
                    throw new ApiException(ApiException.Type.INTERNAL_ERROR);
                }

                try {
                    msg.setResponseHeader(
                            API.getDefaultResponseHeader("application/pkix-cert;", pem.length())
                                    + "Content-Disposition: attachment; filename=\"ZAPCACert.cer\"\r\n");
                } catch (HttpMalformedHeaderException e) {
                    LOGGER.error(e.getMessage(), e);
                    throw new ApiException(ApiException.Type.INTERNAL_ERROR);
                }

                msg.setResponseBody(pem);
                return msg;

            default:
                throw new ApiException(ApiException.Type.BAD_OTHER);
        }
    }
}
