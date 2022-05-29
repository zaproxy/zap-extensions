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
import java.net.PasswordAuthentication;
import java.net.ServerSocket;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.internal.cert.CertificateUtils;
import org.zaproxy.addon.network.internal.client.HttpProxy;
import org.zaproxy.addon.network.internal.client.HttpProxyExclusion;
import org.zaproxy.addon.network.internal.client.SocksProxy;
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
import org.zaproxy.zap.utils.ApiUtils;

public class NetworkApi extends ApiImplementor {

    private static final Logger LOGGER = LogManager.getLogger(NetworkApi.class);

    private static final String PREFIX = "network";

    private static final String ACTION_ADD_ALIAS = "addAlias";
    private static final String ACTION_ADD_HTTP_PROXY_EXCLUSION = "addHttpProxyExclusion";
    private static final String ACTION_ADD_LOCAL_SERVER = "addLocalServer";
    private static final String ACTION_ADD_PASS_THROUGH = "addPassThrough";
    private static final String ACTION_ADD_PKCS12_CLIENT_CERTIFICATE = "addPkcs12ClientCertificate";
    private static final String ACTION_GENERATE_ROOT_CA_CERT = "generateRootCaCert";
    private static final String ACTION_IMPORT_ROOT_CA_CERT = "importRootCaCert";
    private static final String ACTION_REMOVE_ALIAS = "removeAlias";
    private static final String ACTION_REMOVE_HTTP_PROXY_EXCLUSION = "removeHttpProxyExclusion";
    private static final String ACTION_REMOVE_LOCAL_SERVER = "removeLocalServer";
    private static final String ACTION_REMOVE_PASS_THROUGH = "removePassThrough";
    private static final String ACTION_SET_ALIAS_ENABLED = "setAliasEnabled";
    private static final String ACTION_SET_CONNECTION_TIMEOUT = "setConnectionTimeout";
    private static final String ACTION_SET_DEFAULT_USER_AGENT = "setDefaultUserAgent";
    private static final String ACTION_SET_DNS_TTL_SUCCESSFUL_QUERIES =
            "setDnsTtlSuccessfulQueries";
    private static final String ACTION_SET_HTTP_PROXY = "setHttpProxy";
    private static final String ACTION_SET_HTTP_PROXY_AUTH_ENABLED = "setHttpProxyAuthEnabled";
    private static final String ACTION_SET_HTTP_PROXY_ENABLED = "setHttpProxyEnabled";
    private static final String ACTION_SET_HTTP_PROXY_EXCLUSION_ENABLED =
            "setHttpProxyExclusionEnabled";
    private static final String ACTION_SET_PASS_THROUGH_ENABLED = "setPassThroughEnabled";
    private static final String ACTION_SET_ROOT_CA_CERT_VALIDITY = "setRootCaCertValidity";
    private static final String ACTION_SET_SERVER_CERT_VALIDITY = "setServerCertValidity";
    private static final String ACTION_SET_SOCKS_PROXY = "setSocksProxy";
    private static final String ACTION_SET_SOCKS_PROXY_ENABLED = "setSocksProxyEnabled";
    private static final String ACTION_SET_USE_CLIENT_CERTIFICATE = "setUseClientCertificate";
    private static final String ACTION_SET_USE_GLOBAL_HTTP_STATE = "setUseGlobalHttpState";

    private static final String VIEW_GET_ALIASES = "getAliases";
    private static final String VIEW_GET_CONNECTION_TIMEOUT = "getConnectionTimeout";
    private static final String VIEW_GET_HTTP_PROXY = "getHttpProxy";
    private static final String VIEW_GET_HTTP_PROXY_EXCLUSIONS = "getHttpProxyExclusions";
    private static final String VIEW_GET_LOCAL_SERVERS = "getLocalServers";
    private static final String VIEW_GET_PASS_THROUGHS = "getPassThroughs";
    private static final String VIEW_GET_ROOT_CA_CERT_VALIDITY = "getRootCaCertValidity";
    private static final String VIEW_GET_SERVER_CERT_VALIDITY = "getServerCertValidity";
    private static final String VIEW_GET_SOCKS_PROXY = "getSocksProxy";
    private static final String VIEW_IS_HTTP_PROXY_AUTH_ENABLED = "isHttpProxyAuthEnabled";
    private static final String VIEW_IS_HTTP_PROXY_ENABLED = "isHttpProxyEnabled";
    private static final String VIEW_IS_SOCKS_PROXY_ENABLED = "isSocksProxyEnabled";
    private static final String VIEW_IS_USE_GLOBAL_HTTP_STATE = "isUseGlobalHttpState";
    private static final String VIEW_GET_DEFAULT_USER_AGENT = "getDefaultUserAgent";
    private static final String VIEW_GET_DNS_TTL_SUCCESSFUL_QUERIES = "getDnsTtlSuccessfulQueries";

    private static final String OTHER_PROXY_PAC = "proxy.pac";
    private static final String OTHER_ROOT_CA_CERT = "rootCaCert";
    private static final String OTHER_SET_PROXY = "setProxy";

    private static final String SHORTCUT_SET_PROXY = "setproxy";

    private static final String PARAM_ADDRESS = "address";
    private static final String PARAM_API = "api";
    private static final String PARAM_AUTHORITY = "authority";
    private static final String PARAM_BEHIND_NAT = "behindNat";
    private static final String PARAM_DECODE_RESPONSE = "decodeResponse";
    private static final String PARAM_ENABLED = "enabled";
    private static final String PARAM_FILE_PATH = "filePath";
    private static final String PARAM_HOST = "host";
    private static final String PARAM_INDEX = "index";
    private static final String PARAM_NAME = "name";
    private static final String PARAM_PASSWORD = "password";
    private static final String PARAM_PORT = "port";
    private static final String PARAM_PROXY = "proxy";
    private static final String PARAM_REALM = "realm";
    private static final String PARAM_REMOVE_ACCEPT_ENCODING = "removeAcceptEncoding";
    private static final String PARAM_TIMEOUT = "timeout";
    private static final String PARAM_TTL = "ttl";
    private static final String PARAM_USE_DNS = "useDns";
    private static final String PARAM_USERNAME = "username";
    private static final String PARAM_VALIDITY = "validity";
    private static final String PARAM_VERSION = "version";
    private static final String PARAM_USE = "use";
    private static final String PARAM_USER_AGENT = "userAgent";

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

            this.addApiOthers(new ApiOther(OTHER_PROXY_PAC, false));
            this.addApiShortcut(OTHER_PROXY_PAC);
        }

        if (isHandleConnection(extensionNetwork)) {
            this.addApiOthers(new ApiOther(OTHER_SET_PROXY, Arrays.asList(PARAM_PROXY)));
            this.addApiShortcut(SHORTCUT_SET_PROXY);

            this.addApiAction(
                    new ApiAction(ACTION_SET_CONNECTION_TIMEOUT, Arrays.asList(PARAM_TIMEOUT)));
            this.addApiAction(
                    new ApiAction(ACTION_SET_DEFAULT_USER_AGENT, Arrays.asList(PARAM_USER_AGENT)));
            this.addApiAction(
                    new ApiAction(ACTION_SET_DNS_TTL_SUCCESSFUL_QUERIES, Arrays.asList(PARAM_TTL)));
            this.addApiAction(
                    new ApiAction(
                            ACTION_ADD_HTTP_PROXY_EXCLUSION,
                            Arrays.asList(PARAM_HOST),
                            Arrays.asList(PARAM_ENABLED)));
            this.addApiAction(
                    new ApiAction(ACTION_REMOVE_HTTP_PROXY_EXCLUSION, Arrays.asList(PARAM_HOST)));
            this.addApiAction(
                    new ApiAction(
                            ACTION_SET_HTTP_PROXY,
                            Arrays.asList(PARAM_HOST, PARAM_PORT),
                            Arrays.asList(PARAM_REALM, PARAM_USERNAME, PARAM_PASSWORD)));
            this.addApiAction(
                    new ApiAction(
                            ACTION_SET_HTTP_PROXY_AUTH_ENABLED, Arrays.asList(PARAM_ENABLED)));
            this.addApiAction(
                    new ApiAction(ACTION_SET_HTTP_PROXY_ENABLED, Arrays.asList(PARAM_ENABLED)));
            this.addApiAction(
                    new ApiAction(
                            ACTION_SET_HTTP_PROXY_EXCLUSION_ENABLED,
                            Arrays.asList(PARAM_HOST, PARAM_ENABLED)));
            this.addApiAction(
                    new ApiAction(
                            ACTION_SET_SOCKS_PROXY,
                            Arrays.asList(PARAM_HOST, PARAM_PORT),
                            Arrays.asList(
                                    PARAM_VERSION, PARAM_USE_DNS, PARAM_USERNAME, PARAM_PASSWORD)));
            this.addApiAction(
                    new ApiAction(ACTION_SET_SOCKS_PROXY_ENABLED, Arrays.asList(PARAM_ENABLED)));
            this.addApiAction(
                    new ApiAction(ACTION_SET_USE_GLOBAL_HTTP_STATE, Arrays.asList(PARAM_USE)));

            this.addApiView(new ApiView(VIEW_GET_CONNECTION_TIMEOUT));
            this.addApiView(new ApiView(VIEW_GET_DEFAULT_USER_AGENT));
            this.addApiView(new ApiView(VIEW_GET_DNS_TTL_SUCCESSFUL_QUERIES));
            this.addApiView(new ApiView(VIEW_GET_HTTP_PROXY));
            this.addApiView(new ApiView(VIEW_GET_HTTP_PROXY_EXCLUSIONS));
            this.addApiView(new ApiView(VIEW_GET_SOCKS_PROXY));
            this.addApiView(new ApiView(VIEW_IS_HTTP_PROXY_AUTH_ENABLED));
            this.addApiView(new ApiView(VIEW_IS_HTTP_PROXY_ENABLED));
            this.addApiView(new ApiView(VIEW_IS_SOCKS_PROXY_ENABLED));
            this.addApiView(new ApiView(VIEW_IS_USE_GLOBAL_HTTP_STATE));
        }

        if (isHandleClientCerts(extensionNetwork)) {
            addApiAction(
                    new ApiAction(
                            ACTION_ADD_PKCS12_CLIENT_CERTIFICATE,
                            Arrays.asList(PARAM_FILE_PATH, PARAM_PASSWORD),
                            Arrays.asList(PARAM_INDEX)));
            addApiAction(
                    new ApiAction(ACTION_SET_USE_CLIENT_CERTIFICATE, Arrays.asList(PARAM_USE)));
        }

        this.addApiOthers(new ApiOther(OTHER_ROOT_CA_CERT, false));
    }

    private static boolean isHandleServerCerts(ExtensionNetwork extensionNetwork) {
        return extensionNetwork == null || extensionNetwork.isHandleServerCerts();
    }

    private static boolean isHandleLocalServers(ExtensionNetwork extensionNetwork) {
        return extensionNetwork == null || extensionNetwork.isHandleLocalServers();
    }

    private static boolean isHandleConnection(ExtensionNetwork extensionNetwork) {
        return extensionNetwork == null || ExtensionNetwork.isHandleConnection();
    }

    private static boolean isHandleClientCerts(ExtensionNetwork extensionNetwork) {
        return extensionNetwork == null || extensionNetwork.isHandleClientCerts();
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
            case ACTION_ADD_HTTP_PROXY_EXCLUSION:
                {
                    if (!isHandleConnection(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_ACTION);
                    }
                    Pattern host = createHostPattern(params.getString(PARAM_HOST));
                    boolean enabled = getParam(params, PARAM_ENABLED, true);
                    HttpProxyExclusion exclusion = new HttpProxyExclusion(host, enabled);
                    extensionNetwork.getConnectionOptions().addHttpProxyExclusion(exclusion);
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
            case ACTION_ADD_PKCS12_CLIENT_CERTIFICATE:
                {
                    if (!isHandleClientCerts(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_ACTION);
                    }
                    String file = params.getString(PARAM_FILE_PATH);
                    String password = params.getString(PARAM_PASSWORD);
                    int index = ApiUtils.getIntParam(params, PARAM_INDEX);
                    ClientCertificatesOptions options =
                            extensionNetwork.getClientCertificatesOptions();
                    options.setPkcs12File(file);
                    options.setPkcs12Password(password);
                    options.setPkcs12Index(index);
                    if (!options.addPkcs12Certificate()) {
                        throw new ApiException(
                                ApiException.Type.BAD_EXTERNAL_DATA,
                                "Failed to add the certificate.");
                    }
                    options.setUseCertificate(true);
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
            case ACTION_REMOVE_HTTP_PROXY_EXCLUSION:
                {
                    if (!isHandleConnection(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_ACTION);
                    }
                    String host = params.getString(PARAM_HOST);
                    boolean removed =
                            extensionNetwork.getConnectionOptions().removeHttpProxyExclusion(host);
                    if (!removed) {
                        throw new ApiException(ApiException.Type.DOES_NOT_EXIST, PARAM_HOST);
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
            case ACTION_SET_CONNECTION_TIMEOUT:
                {
                    if (!isHandleConnection(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_ACTION);
                    }
                    int timeout = ApiUtils.getIntParam(params, PARAM_TIMEOUT);
                    extensionNetwork.getConnectionOptions().setTimeoutInSecs(timeout);
                    return ApiResponseElement.OK;
                }
            case ACTION_SET_DEFAULT_USER_AGENT:
                {
                    if (!isHandleConnection(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_ACTION);
                    }
                    String userAgent = params.getString(PARAM_USER_AGENT);
                    extensionNetwork.getConnectionOptions().setDefaultUserAgent(userAgent);
                    return ApiResponseElement.OK;
                }
            case ACTION_SET_DNS_TTL_SUCCESSFUL_QUERIES:
                {
                    if (!isHandleConnection(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_ACTION);
                    }
                    int ttl = ApiUtils.getIntParam(params, PARAM_TTL);
                    extensionNetwork.getConnectionOptions().setDnsTtlSuccessfulQueries(ttl);
                    return ApiResponseElement.OK;
                }
            case ACTION_SET_HTTP_PROXY:
                {
                    if (!isHandleConnection(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_ACTION);
                    }
                    String host = params.getString(PARAM_HOST);
                    int port = getParam(params, PARAM_PORT, -1);
                    if (!isValidPort(port)) {
                        throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, PARAM_PORT);
                    }
                    String realm = params.optString(PARAM_REALM);
                    String username = params.optString(PARAM_USERNAME);
                    String password = params.optString(PARAM_PASSWORD);

                    extensionNetwork
                            .getConnectionOptions()
                            .setHttpProxy(
                                    new HttpProxy(
                                            host,
                                            port,
                                            realm,
                                            new PasswordAuthentication(
                                                    username, password.toCharArray())));
                    return ApiResponseElement.OK;
                }
            case ACTION_SET_HTTP_PROXY_AUTH_ENABLED:
                {
                    if (!isHandleConnection(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_ACTION);
                    }
                    boolean enabled = getParam(params, PARAM_ENABLED, false);
                    extensionNetwork.getConnectionOptions().setHttpProxyAuthEnabled(enabled);
                    return ApiResponseElement.OK;
                }
            case ACTION_SET_HTTP_PROXY_ENABLED:
                {
                    if (!isHandleConnection(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_ACTION);
                    }
                    boolean enabled = getParam(params, PARAM_ENABLED, false);
                    extensionNetwork.getConnectionOptions().setHttpProxyEnabled(enabled);
                    return ApiResponseElement.OK;
                }
            case ACTION_SET_HTTP_PROXY_EXCLUSION_ENABLED:
                {
                    if (!isHandleConnection(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_ACTION);
                    }
                    String host = params.getString(PARAM_HOST);
                    boolean enabled = getParam(params, PARAM_ENABLED, true);
                    boolean changed =
                            extensionNetwork
                                    .getConnectionOptions()
                                    .setHttpProxyExclusionEnabled(host, enabled);
                    if (!changed) {
                        throw new ApiException(ApiException.Type.DOES_NOT_EXIST, PARAM_HOST);
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
            case ACTION_SET_SOCKS_PROXY:
                {
                    if (!isHandleConnection(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_ACTION);
                    }
                    String host = params.getString(PARAM_HOST);
                    int port = getParam(params, PARAM_PORT, -1);
                    if (!isValidPort(port)) {
                        throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, PARAM_PORT);
                    }
                    SocksProxy.Version version =
                            SocksProxy.Version.from(params.optString(PARAM_VERSION));
                    boolean useDns =
                            getParam(
                                    params,
                                    PARAM_USE_DNS,
                                    ConnectionOptions.DEFAULT_SOCKS_PROXY.isUseDns());
                    String username = params.optString(PARAM_USERNAME);
                    String password = params.optString(PARAM_PASSWORD);

                    extensionNetwork
                            .getConnectionOptions()
                            .setSocksProxy(
                                    new SocksProxy(
                                            host,
                                            port,
                                            version,
                                            useDns,
                                            new PasswordAuthentication(
                                                    username, password.toCharArray())));
                    return ApiResponseElement.OK;
                }
            case ACTION_SET_SOCKS_PROXY_ENABLED:
                {
                    if (!isHandleConnection(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_ACTION);
                    }
                    boolean enabled = getParam(params, PARAM_ENABLED, false);
                    extensionNetwork.getConnectionOptions().setSocksProxyEnabled(enabled);
                    return ApiResponseElement.OK;
                }
            case ACTION_SET_USE_GLOBAL_HTTP_STATE:
                {
                    if (!isHandleConnection(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_ACTION);
                    }
                    boolean use = getParam(params, PARAM_USE, false);
                    extensionNetwork.getConnectionOptions().setUseGlobalHttpState(use);
                    return ApiResponseElement.OK;
                }
            case ACTION_SET_USE_CLIENT_CERTIFICATE:
                {
                    if (!isHandleClientCerts(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_ACTION);
                    }
                    boolean use = getParam(params, PARAM_USE, false);
                    extensionNetwork.getClientCertificatesOptions().setUseCertificate(use);
                    return ApiResponseElement.OK;
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

    private static Pattern createHostPattern(String value) throws ApiException {
        try {
            return HttpProxyExclusion.createHostPattern(value);
        } catch (IllegalArgumentException e) {
            throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, PARAM_HOST, e);
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
            case VIEW_GET_CONNECTION_TIMEOUT:
                {
                    if (!isHandleConnection(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_VIEW);
                    }
                    int timeout = extensionNetwork.getConnectionOptions().getTimeoutInSecs();
                    return new ApiResponseElement(name, String.valueOf(timeout));
                }
            case VIEW_GET_DEFAULT_USER_AGENT:
                {
                    if (!isHandleConnection(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_VIEW);
                    }
                    String userAgent =
                            extensionNetwork.getConnectionOptions().getDefaultUserAgent();
                    return new ApiResponseElement(name, userAgent);
                }
            case VIEW_GET_DNS_TTL_SUCCESSFUL_QUERIES:
                {
                    if (!isHandleConnection(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_VIEW);
                    }
                    int ttl = extensionNetwork.getConnectionOptions().getDnsTtlSuccessfulQueries();
                    return new ApiResponseElement(name, String.valueOf(ttl));
                }
            case VIEW_GET_HTTP_PROXY:
                {
                    if (!isHandleConnection(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_VIEW);
                    }
                    HttpProxy proxy = extensionNetwork.getConnectionOptions().getHttpProxy();
                    Map<String, Object> proxyData = new LinkedHashMap<>();
                    proxyData.put("host", proxy.getHost());
                    proxyData.put("port", proxy.getPort());
                    proxyData.put("realm", proxy.getRealm());
                    PasswordAuthentication credentials = proxy.getPasswordAuthentication();
                    proxyData.put("username", credentials.getUserName());
                    proxyData.put("password", new String(credentials.getPassword()));
                    return new ApiResponseElement(new ApiResponseSet<>(name, proxyData));
                }
            case VIEW_GET_HTTP_PROXY_EXCLUSIONS:
                {
                    if (!isHandleConnection(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_VIEW);
                    }
                    ApiResponseList response = new ApiResponseList(name);
                    for (HttpProxyExclusion exclusion :
                            extensionNetwork.getConnectionOptions().getHttpProxyExclusions()) {
                        Map<String, Object> entry = new HashMap<>();
                        entry.put("host", exclusion.getHost().pattern());
                        entry.put("enabled", exclusion.isEnabled());
                        response.addItem(new ApiResponseSet<>("exclusion", entry));
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
                    entry.put("authority", passThrough.getAuthority().pattern());
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
            case VIEW_GET_SOCKS_PROXY:
                {
                    if (!isHandleConnection(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_VIEW);
                    }
                    SocksProxy proxy = extensionNetwork.getConnectionOptions().getSocksProxy();
                    Map<String, Object> proxyData = new LinkedHashMap<>();
                    proxyData.put("host", proxy.getHost());
                    proxyData.put("port", proxy.getPort());
                    proxyData.put("version", String.valueOf(proxy.getVersion().number()));
                    proxyData.put("useDns", proxy.isUseDns());
                    PasswordAuthentication credentials = proxy.getPasswordAuthentication();
                    proxyData.put("username", credentials.getUserName());
                    proxyData.put("password", new String(credentials.getPassword()));
                    return new ApiResponseElement(new ApiResponseSet<>(name, proxyData));
                }
            case VIEW_IS_HTTP_PROXY_AUTH_ENABLED:
                {
                    if (!isHandleConnection(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_VIEW);
                    }
                    return new ApiResponseElement(
                            name,
                            String.valueOf(
                                    extensionNetwork
                                            .getConnectionOptions()
                                            .isHttpProxyAuthEnabled()));
                }
            case VIEW_IS_HTTP_PROXY_ENABLED:
                {
                    if (!isHandleConnection(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_VIEW);
                    }
                    return new ApiResponseElement(
                            name,
                            String.valueOf(
                                    extensionNetwork.getConnectionOptions().isHttpProxyEnabled()));
                }
            case VIEW_IS_SOCKS_PROXY_ENABLED:
                {
                    if (!isHandleConnection(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_VIEW);
                    }
                    return new ApiResponseElement(
                            name,
                            String.valueOf(
                                    extensionNetwork.getConnectionOptions().isSocksProxyEnabled()));
                }
            case VIEW_IS_USE_GLOBAL_HTTP_STATE:
                {
                    if (!isHandleConnection(extensionNetwork)) {
                        throw new ApiException(ApiException.Type.BAD_VIEW);
                    }
                    return new ApiResponseElement(
                            name,
                            String.valueOf(
                                    extensionNetwork
                                            .getConnectionOptions()
                                            .isUseGlobalHttpState()));
                }

            default:
                throw new ApiException(ApiException.Type.BAD_VIEW);
        }
    }

    @Override
    public HttpMessage handleApiOther(HttpMessage msg, String name, JSONObject params)
            throws ApiException {
        switch (name) {
            case OTHER_PROXY_PAC:
                if (!isHandleLocalServers(extensionNetwork)) {
                    throw new ApiException(ApiException.Type.BAD_OTHER);
                }
                try {
                    String response =
                            extensionNetwork.getProxyPacContent(
                                    msg.getRequestHeader().getHostName());
                    msg.setResponseHeader(
                            API.getDefaultResponseHeader("text/html", response.length()));
                    msg.setResponseBody(response);
                } catch (Exception e) {
                    LOGGER.error(e.getMessage(), e);
                }
                return msg;

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

            case OTHER_SET_PROXY:
                if (!isHandleConnection(extensionNetwork)) {
                    throw new ApiException(ApiException.Type.BAD_OTHER);
                }

                /* JSON string:
                 *  {"type":1,
                 *  "http":	{"host":"proxy.corp.com","port":80},
                 *  "ssl":	{"host":"proxy.corp.com","port":80},
                 *  "ftp":{"host":"proxy.corp.com","port":80},
                 *  "socks":{"host":"proxy.corp.com","port":80},
                 *  "shareSettings":true,"socksVersion":5,
                 *  "proxyExcludes":"localhost, 127.0.0.1"}
                 */
                try {
                    JSONObject json = JSONObject.fromObject(params.getString(PARAM_PROXY));

                    if (json.optInt("type", -1) == 1) {
                        JSONObject httpJson = JSONObject.fromObject(json.get("http"));
                        String host = httpJson.optString("host", null);
                        int port = httpJson.optInt("port", -1);

                        if (isValidPort(port) && host != null && !host.isEmpty()) {
                            HttpProxy oldProxy =
                                    extensionNetwork.getConnectionOptions().getHttpProxy();
                            HttpProxy httpProxy =
                                    new HttpProxy(
                                            host,
                                            port,
                                            oldProxy.getRealm(),
                                            oldProxy.getPasswordAuthentication());
                            extensionNetwork.getConnectionOptions().setHttpProxy(httpProxy);
                        }
                    }

                    String response = "OK";
                    msg.setResponseHeader(
                            API.getDefaultResponseHeader("text/html", response.length()));

                    msg.setResponseBody(response);

                } catch (JSONException e) {
                    throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, PARAM_PROXY);
                } catch (Exception e) {
                    LOGGER.error(e.getMessage(), e);
                }

                return msg;

            default:
                throw new ApiException(ApiException.Type.BAD_OTHER);
        }
    }

    private static boolean isValidPort(int port) {
        return port > 0 && port <= 65535;
    }

    @Override
    public HttpMessage handleShortcut(HttpMessage msg) throws ApiException {
        if (isHandleLocalServers(extensionNetwork)
                && msg.getRequestHeader()
                        .getURI()
                        .getEscapedPath()
                        .startsWith("/" + OTHER_PROXY_PAC)) {
            return handleApiOther(msg, OTHER_PROXY_PAC, new JSONObject());
        }

        if (isHandleConnection(extensionNetwork)
                && msg.getRequestHeader()
                        .getURI()
                        .getEscapedPath()
                        .startsWith("/" + SHORTCUT_SET_PROXY)) {
            JSONObject params = new JSONObject();
            params.put(PARAM_PROXY, msg.getRequestBody().toString());
            return this.handleApiOther(msg, OTHER_SET_PROXY, params);
        }

        throw new ApiException(
                ApiException.Type.URL_NOT_FOUND, msg.getRequestHeader().getURI().toString());
    }
}
