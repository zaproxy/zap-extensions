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

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.internal.cert.CertificateUtils;
import org.zaproxy.addon.network.internal.server.http.Alias;
import org.zaproxy.addon.network.internal.server.http.LocalServerConfig;
import org.zaproxy.addon.network.internal.server.http.LocalServerConfig.ServerMode;
import org.zaproxy.addon.network.internal.server.http.PassThrough;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiOther;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.api.ApiView;

public class NetworkApi extends ApiImplementor {

    private static final Logger LOGGER = LogManager.getLogger(NetworkApi.class);

    private static final String PREFIX = "network";

    private static final String ACTION_ADD_ALIAS = "addAlias";
    private static final String ACTION_ADD_LOCAL_SERVER = "addLocalServer";
    private static final String ACTION_ADD_PASS_THROUGH = "addPassThrough";
    private static final String ACTION_GENERATE_ROOT_CA_CERT = "generateRootCaCert";
    private static final String ACTION_IMPORT_ROOT_CA_CERT = "importRootCaCert";
    private static final String ACTION_REMOVE_ALIAS = "removeAlias";
    private static final String ACTION_REMOVE_LOCAL_SERVER = "removeLocalServer";
    private static final String ACTION_REMOVE_PASS_THROUGH = "removePassThrough";
    private static final String ACTION_SET_ALIAS_ENABLED = "setAliasEnabled";
    private static final String ACTION_SET_PASS_THROUGH_ENABLED = "setPassThroughEnabled";
    private static final String ACTION_SET_ROOT_CA_CERT_VALIDITY = "setRootCaCertValidity";
    private static final String ACTION_SET_SERVER_CERT_VALIDITY = "setServerCertValidity";

    private static final String VIEW_GET_ALIASES = "getAliases";
    private static final String VIEW_GET_LOCAL_SERVERS = "getLocalServers";
    private static final String VIEW_GET_PASS_THROUGHS = "getPassThroughs";
    private static final String VIEW_GET_ROOT_CA_CERT_VALIDITY = "getRootCaCertValidity";
    private static final String VIEW_GET_SERVER_CERT_VALIDITY = "getServerCertValidity";

    private static final String OTHER_ROOT_CA_CERT = "rootCaCert";

    private static final String PARAM_ADDRESS = "address";
    private static final String PARAM_API = "api";
    private static final String PARAM_AUTHORITY = "authority";
    private static final String PARAM_BEHIND_NAT = "behindNat";
    private static final String PARAM_DECODE_RESPONSE = "decodeResponse";
    private static final String PARAM_ENABLED = "enabled";
    private static final String PARAM_FILE_PATH = "filePath";
    private static final String PARAM_NAME = "name";
    private static final String PARAM_PORT = "port";
    private static final String PARAM_PROXY = "proxy";
    private static final String PARAM_REMOVE_ACCEPT_ENCODING = "removeAcceptEncoding";
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

        if (isHandleLocalServers(extensionNetwork)) {
            this.addApiAction(
                    new ApiAction(
                            ACTION_ADD_ALIAS,
                            Arrays.asList(PARAM_NAME),
                            Arrays.asList(PARAM_ENABLED)));
            this.addApiAction(
                    new ApiAction(
                            ACTION_ADD_LOCAL_SERVER,
                            Arrays.asList(PARAM_ADDRESS, PARAM_PORT),
                            Arrays.asList(
                                    PARAM_API,
                                    PARAM_PROXY,
                                    PARAM_BEHIND_NAT,
                                    PARAM_DECODE_RESPONSE,
                                    PARAM_REMOVE_ACCEPT_ENCODING)));
            this.addApiAction(
                    new ApiAction(
                            ACTION_ADD_PASS_THROUGH,
                            Arrays.asList(PARAM_AUTHORITY),
                            Arrays.asList(PARAM_ENABLED)));
            this.addApiAction(new ApiAction(ACTION_REMOVE_ALIAS, Arrays.asList(PARAM_NAME)));
            this.addApiAction(
                    new ApiAction(
                            ACTION_REMOVE_LOCAL_SERVER, Arrays.asList(PARAM_ADDRESS, PARAM_PORT)));
            this.addApiAction(
                    new ApiAction(ACTION_REMOVE_PASS_THROUGH, Arrays.asList(PARAM_AUTHORITY)));
            this.addApiAction(
                    new ApiAction(
                            ACTION_SET_ALIAS_ENABLED, Arrays.asList(PARAM_NAME, PARAM_ENABLED)));
            this.addApiAction(
                    new ApiAction(
                            ACTION_SET_PASS_THROUGH_ENABLED,
                            Arrays.asList(PARAM_AUTHORITY, PARAM_ENABLED)));

            this.addApiView(new ApiView(VIEW_GET_ALIASES));
            this.addApiView(new ApiView(VIEW_GET_LOCAL_SERVERS));
            this.addApiView(new ApiView(VIEW_GET_PASS_THROUGHS));
        }

        this.addApiOthers(new ApiOther(OTHER_ROOT_CA_CERT, false));
    }

    private static boolean isHandleServerCerts(ExtensionNetwork extensionNetwork) {
        return extensionNetwork == null || extensionNetwork.isHandleServerCerts();
    }

    private static boolean isHandleLocalServers(ExtensionNetwork extensionNetwork) {
        return extensionNetwork == null || extensionNetwork.isHandleLocalServers();
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        switch (name) {
            case ACTION_ADD_ALIAS:
                {
                    if (!isHandleLocalServers(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_ACTION);
                    }
                    String aliasName = params.getString(PARAM_NAME);
                    boolean enabled = getParam(params, PARAM_ENABLED, true);
                    Alias alias = new Alias(aliasName, enabled);
                    extensionNetwork.getLocalServersOptions().addAlias(alias);
                    return ApiResponseElement.OK;
                }
            case ACTION_ADD_LOCAL_SERVER:
                {
                    if (!isHandleLocalServers(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_ACTION);
                    }
                    LocalServerConfig server = new LocalServerConfig();
                    server.setAddress(params.getString(PARAM_ADDRESS));
                    try {
                        server.setPort(
                                getParam(params, PARAM_PORT, LocalServerConfig.DEFAULT_PORT));
                    } catch (IllegalArgumentException e) {
                        throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, PARAM_PORT);
                    }
                    boolean proxy = getParam(params, PARAM_PROXY, true);
                    boolean api = getParam(params, PARAM_API, true);
                    server.setMode(
                            proxy && api
                                    ? ServerMode.API_AND_PROXY
                                    : proxy ? ServerMode.PROXY : ServerMode.API);
                    server.setBehindNat(getParam(params, PARAM_BEHIND_NAT, false));
                    server.setRemoveAcceptEncoding(
                            getParam(params, PARAM_REMOVE_ACCEPT_ENCODING, true));
                    server.setDecodeResponse(getParam(params, PARAM_DECODE_RESPONSE, true));
                    validateLocalServer(server);
                    extensionNetwork.getLocalServersOptions().addServer(server);
                    return ApiResponseElement.OK;
                }
            case ACTION_ADD_PASS_THROUGH:
                {
                    if (!isHandleLocalServers(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_ACTION);
                    }
                    Pattern authority = createAuthorityPattern(params.getString(PARAM_AUTHORITY));
                    boolean enabled = getParam(params, PARAM_ENABLED, true);
                    PassThrough passThrough = new PassThrough(authority, enabled);
                    extensionNetwork.getLocalServersOptions().addPassThrough(passThrough);
                    return ApiResponseElement.OK;
                }

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
            case ACTION_REMOVE_ALIAS:
                {
                    if (!isHandleLocalServers(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_ACTION);
                    }
                    String aliasName = params.getString(PARAM_NAME);
                    boolean removed =
                            extensionNetwork.getLocalServersOptions().removeAlias(aliasName);
                    if (!removed) {
                        throw new ApiException(ApiException.Type.DOES_NOT_EXIST, PARAM_NAME);
                    }
                    return ApiResponseElement.OK;
                }
            case ACTION_REMOVE_LOCAL_SERVER:
                {
                    if (!isHandleLocalServers(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_ACTION);
                    }
                    String address = params.getString(PARAM_ADDRESS);
                    int port = getParam(params, PARAM_PORT, LocalServerConfig.DEFAULT_PORT);
                    boolean removed =
                            extensionNetwork.getLocalServersOptions().removeServer(address, port);
                    if (!removed) {
                        throw new ApiException(ApiException.Type.DOES_NOT_EXIST);
                    }
                    return ApiResponseElement.OK;
                }
            case ACTION_REMOVE_PASS_THROUGH:
                {
                    if (!isHandleLocalServers(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_ACTION);
                    }
                    String authority = params.getString(PARAM_AUTHORITY);
                    boolean removed =
                            extensionNetwork.getLocalServersOptions().removePassThrough(authority);
                    if (!removed) {
                        throw new ApiException(ApiException.Type.DOES_NOT_EXIST, PARAM_AUTHORITY);
                    }
                    return ApiResponseElement.OK;
                }
            case ACTION_SET_ALIAS_ENABLED:
                {
                    if (!isHandleLocalServers(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_ACTION);
                    }
                    String aliasName = params.getString(PARAM_NAME);
                    boolean enabled = getParam(params, PARAM_ENABLED, true);
                    boolean changed =
                            extensionNetwork
                                    .getLocalServersOptions()
                                    .setAliasEnabled(aliasName, enabled);
                    if (!changed) {
                        throw new ApiException(ApiException.Type.DOES_NOT_EXIST, PARAM_NAME);
                    }
                    return ApiResponseElement.OK;
                }
            case ACTION_SET_PASS_THROUGH_ENABLED:
                {
                    if (!isHandleLocalServers(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_ACTION);
                    }
                    String authority = params.getString(PARAM_AUTHORITY);
                    boolean enabled = getParam(params, PARAM_ENABLED, true);
                    boolean changed =
                            extensionNetwork
                                    .getLocalServersOptions()
                                    .setPassThroughEnabled(authority, enabled);
                    if (!changed) {
                        throw new ApiException(ApiException.Type.DOES_NOT_EXIST, PARAM_AUTHORITY);
                    }
                    return ApiResponseElement.OK;
                }

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

    private void validateLocalServer(LocalServerConfig server) throws ApiException {
        LocalServersOptions options = extensionNetwork.getLocalServersOptions();
        Set<LocalServerConfig> currentAddresses =
                new TreeSet<>(
                        (o1, o2) -> {
                            int result = Integer.compare(o1.getPort(), o2.getPort());
                            if (result != 0) {
                                return result;
                            }
                            return o1.getAddress().compareToIgnoreCase(o2.getAddress());
                        });

        currentAddresses.add(options.getMainProxy());
        options.getServers().forEach(currentAddresses::add);

        if (!currentAddresses.add(server)) {
            throw new ApiException(
                    ApiException.Type.ILLEGAL_PARAMETER,
                    "A local server/proxy with this address and port is already defined: "
                            + server.getAddress()
                            + ":"
                            + server.getPort());
        }

        try (ServerSocket socket =
                new ServerSocket(server.getPort(), 0, InetAddress.getByName(server.getAddress()))) {
            socket.getLocalPort();
        } catch (IOException e) {
            throw new ApiException(
                    ApiException.Type.ILLEGAL_PARAMETER,
                    "Unable to listen on this address and port: "
                            + server.getAddress()
                            + ":"
                            + server.getPort());
        }
    }

    private static Pattern createAuthorityPattern(String value) throws ApiException {
        try {
            return PassThrough.createAuthorityPattern(value);
        } catch (IllegalArgumentException e) {
            throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, PARAM_AUTHORITY, e);
        }
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        switch (name) {
            case VIEW_GET_ALIASES:
                {
                    if (!isHandleLocalServers(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_VIEW);
                    }
                    ApiResponseList response = new ApiResponseList(name);
                    for (Alias alias : extensionNetwork.getLocalServersOptions().getAliases()) {
                        Map<String, Object> entry = new HashMap<>();
                        entry.put("name", alias.getName());
                        entry.put("enabled", alias.isEnabled());
                        response.addItem(new ApiResponseSet<>("alias", entry));
                    }
                    return response;
                }
            case VIEW_GET_LOCAL_SERVERS:
                {
                    if (!isHandleLocalServers(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_VIEW);
                    }
                    ApiResponseList response = new ApiResponseList(name);
                    for (LocalServerConfig server :
                            extensionNetwork.getLocalServersOptions().getServers()) {
                        Map<String, Object> entry = new HashMap<>();
                        entry.put("address", server.getAddress());
                        entry.put("port", server.getPort());
                        entry.put("api", server.getMode().hasApi());
                        entry.put("proxy", server.getMode().hasProxy());
                        entry.put("behindNat", server.isBehindNat());
                        entry.put("removeAcceptEncoding", server.isRemoveAcceptEncoding());
                        entry.put("decodeResponse", server.isDecodeResponse());
                        entry.put("enabled", server.isEnabled());
                        response.addItem(new ApiResponseSet<>("localServer", entry));
                    }
                    return response;
                }
            case VIEW_GET_PASS_THROUGHS:
                if (!isHandleLocalServers(extensionNetwork)) {
                    throw new ApiException(ApiException.Type.BAD_VIEW);
                }
                ApiResponseList response = new ApiResponseList(name);
                for (PassThrough passThrough :
                        extensionNetwork.getLocalServersOptions().getPassThroughs()) {
                    Map<String, Object> entry = new HashMap<>();
                    entry.put("name", passThrough.getAuthority().pattern());
                    entry.put("enabled", passThrough.isEnabled());
                    response.addItem(new ApiResponseSet<>("passThrough", entry));
                }
                return response;

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
