/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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

import java.net.PasswordAuthentication;
import java.security.Security;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.apache.commons.configuration.ConversionException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.SSLConnector;
import org.zaproxy.addon.network.internal.TlsUtils;
import org.zaproxy.addon.network.internal.client.HttpProxy;
import org.zaproxy.addon.network.internal.client.HttpProxyExclusion;
import org.zaproxy.addon.network.internal.client.SocksProxy;
import org.zaproxy.addon.network.internal.client.SocksProxy.Version;
import org.zaproxy.zap.common.VersionedAbstractParam;

/** The options related to the connection. */
public class ConnectionOptions extends VersionedAbstractParam {

    private static final Logger LOGGER = LogManager.getLogger(ConnectionOptions.class);

    public static final String DEFAULT_DEFAULT_USER_AGENT =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0";

    /** The default connection timeout (in seconds). */
    public static final int DEFAULT_TIMEOUT = 20;

    /** The default TTL (in seconds) of successful DNS queries. */
    public static final int DNS_DEFAULT_TTL_SUCCESSFUL_QUERIES = 30;

    /**
     * The current version of the configurations. Used to keep track of configuration changes
     * between releases, in case changes/updates are needed.
     *
     * <p>It only needs to be incremented for configuration changes (not releases of the add-on).
     *
     * @see #CONFIG_VERSION_KEY
     * @see #updateConfigsImpl(int)
     */
    private static final int CURRENT_CONFIG_VERSION = 1;

    private static final String BASE_KEY = "network.connection";

    /**
     * The configuration key for the version of the configurations.
     *
     * @see #CURRENT_CONFIG_VERSION
     */
    private static final String CONFIG_VERSION_KEY = BASE_KEY + VERSION_ATTRIBUTE;

    private static final String TIMEOUT_KEY = BASE_KEY + ".timeoutInSecs";
    private static final String DEFAULT_USER_AGENT_KEY = BASE_KEY + ".defaultUserAgent";
    private static final String USE_GLOBAL_HTTP_STATE_KEY = BASE_KEY + ".useGlobalHttpState";
    private static final String DNS_TTL_SUCCESSFUL_QUERIES_KEY =
            BASE_KEY + ".dnsTtlSuccessfulQueries";

    private static final String TLS_PROTOCOLS_KEY = BASE_KEY + ".tlsProtocols";
    private static final String TLS_PROTOCOL_KEY = TLS_PROTOCOLS_KEY + ".protocol";
    private static final String TLS_ALLOW_UNSAFE_RENEGOTIATION =
            TLS_PROTOCOLS_KEY + ".allowUnsafeRenegotiation";

    private static final String HTTP_PROXY_BASE_KEY = BASE_KEY + ".httpProxy.";
    private static final String HTTP_PROXY_ENABLED_KEY = HTTP_PROXY_BASE_KEY + "enabled";
    private static final String HTTP_PROXY_HOST_KEY = HTTP_PROXY_BASE_KEY + "host";
    private static final String HTTP_PROXY_PORT_KEY = HTTP_PROXY_BASE_KEY + "port";
    private static final String HTTP_PROXY_AUTH_ENABLED_KEY = HTTP_PROXY_BASE_KEY + "authEnabled";
    private static final String STORE_HTTP_PROXY_PASS_KEY = HTTP_PROXY_BASE_KEY + "storePass";
    private static final String HTTP_PROXY_REALM_KEY = HTTP_PROXY_BASE_KEY + "realm";
    private static final String HTTP_PROXY_USERNAME_KEY = HTTP_PROXY_BASE_KEY + "username";
    private static final String HTTP_PROXY_PASSWORD_KEY = HTTP_PROXY_BASE_KEY + "password";

    private static final String HTTP_PROXY_EXCLUSIONS_KEY = HTTP_PROXY_BASE_KEY + "exclusions";
    private static final String HTTP_PROXY_EXCLUSION_KEY = HTTP_PROXY_EXCLUSIONS_KEY + ".exclusion";
    private static final String HTTP_PROXY_EXCLUSION_HOST_KEY = "host";
    private static final String HTTP_PROXY_EXCLUSION_ENABLED_KEY = "enabled";
    private static final String HTTP_PROXY_EXCLUSIONS_CONFIRM_REMOVE =
            HTTP_PROXY_EXCLUSIONS_KEY + ".confirmRemove";

    private static final String SOCKS_PROXY_BASE_KEY = BASE_KEY + ".socksProxy.";
    private static final String SOCKS_PROXY_ENABLED_KEY = SOCKS_PROXY_BASE_KEY + "enabled";
    private static final String SOCKS_PROXY_HOST_KEY = SOCKS_PROXY_BASE_KEY + "host";
    private static final String SOCKS_PROXY_PORT_KEY = SOCKS_PROXY_BASE_KEY + "port";
    private static final String SOCKS_PROXY_VERSION_KEY = SOCKS_PROXY_BASE_KEY + "version";
    private static final String SOCKS_PROXY_DNS_KEY = SOCKS_PROXY_BASE_KEY + "dns";
    private static final String SOCKS_PROXY_USERNAME_KEY = SOCKS_PROXY_BASE_KEY + "username";
    private static final String SOCKS_PROXY_PASSWORD_KEY = SOCKS_PROXY_BASE_KEY + "password";

    /** The default HTTP proxy configuration. */
    public static final HttpProxy DEFAULT_HTTP_PROXY =
            new HttpProxy("localhost", 8090, "", new PasswordAuthentication("", new char[0]));

    /** The default SOCKS proxy configuration. */
    public static final SocksProxy DEFAULT_SOCKS_PROXY =
            new SocksProxy(
                    "localhost",
                    1080,
                    Version.SOCKS5,
                    true,
                    new PasswordAuthentication("", new char[0]));

    /**
     * Pattern with loopback names and addresses that should be always resolved (when creating the
     * {@link java.net.InetSocketAddress}).
     *
     * <p>Same pattern used by default proxy selector.
     *
     * @see #shouldResolveRemoteHostname(String)
     */
    private static final Pattern LOOPBACK_PATTERN =
            Pattern.compile("\\Qlocalhost\\E|\\Q127.\\E.*|\\Q[::1]\\E|\\Q0.0.0.0\\E|\\Q[::0]\\E");

    /** The security property for TTL of successful DNS queries. */
    private static final String DNS_TTL_SUCCESSFUL_QUERIES_SECURITY_PROPERTY =
            "networkaddress.cache.ttl";

    private static final boolean DEFAULT_STORE_HTTP_PROXY_PASS = true;

    private List<ChangesListener> changesListeners = new ArrayList<>();

    private int timeoutInSecs = DEFAULT_TIMEOUT;
    private String defaultUserAgent = DEFAULT_DEFAULT_USER_AGENT;
    private boolean useGlobalHttpState;
    private int dnsTtlSuccessfulQueries = DNS_DEFAULT_TTL_SUCCESSFUL_QUERIES;
    private List<String> tlsProtocols = TlsUtils.getSupportedProtocols();
    private boolean allowUnsafeRenegotiation;

    private boolean httpProxyEnabled;
    private HttpProxy httpProxy = DEFAULT_HTTP_PROXY;
    private boolean httpProxyAuthEnabled;
    private boolean storeHttpProxyPass = DEFAULT_STORE_HTTP_PROXY_PASS;
    private List<HttpProxyExclusion> httpProxyExclusions = new ArrayList<>();
    private boolean confirmRemoveHttpProxyExclusion = true;

    private boolean socksProxyEnabled;
    private SocksProxy socksProxy = DEFAULT_SOCKS_PROXY;

    @Override
    protected int getCurrentVersion() {
        return CURRENT_CONFIG_VERSION;
    }

    @Override
    protected String getConfigVersionKey() {
        return CONFIG_VERSION_KEY;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        // Nothing to do.
    }

    @Override
    protected void parseImpl() {
        // Do always, for now, in case -config args are in use.
        migrateCoreConfigs();

        setTimeoutInSecsImpl(getInt(TIMEOUT_KEY, DEFAULT_TIMEOUT));
        setDefaultUserAgentImpl(getString(DEFAULT_USER_AGENT_KEY, DEFAULT_DEFAULT_USER_AGENT));
        useGlobalHttpState = getBoolean(USE_GLOBAL_HTTP_STATE_KEY, false);

        dnsTtlSuccessfulQueries =
                getInt(DNS_TTL_SUCCESSFUL_QUERIES_KEY, DNS_DEFAULT_TTL_SUCCESSFUL_QUERIES);
        Security.setProperty(
                DNS_TTL_SUCCESSFUL_QUERIES_SECURITY_PROPERTY,
                Integer.toString(dnsTtlSuccessfulQueries));

        List<String> protocols =
                getConfig().getList(TLS_PROTOCOL_KEY).stream()
                        .map(Object::toString)
                        .collect(Collectors.toList());
        if (protocols.isEmpty()) {
            protocols = TlsUtils.getSupportedProtocols();
        } else {
            try {
                protocols = TlsUtils.filterUnsupportedProtocols(protocols);
            } catch (Exception e) {
                LOGGER.warn("An error occurred while setting TLS protocols:", e);
                protocols = TlsUtils.getSupportedProtocols();
            }
        }
        tlsProtocols = protocols;
        applyTlsProtocols();
        allowUnsafeRenegotiation = getBoolean(TLS_ALLOW_UNSAFE_RENEGOTIATION, false);
        setAllowUnsafeRenegotiationSystemProperty(allowUnsafeRenegotiation);

        parseHttpProxyOptions();
        parseSocksProxyOptions();

        notifyChangesListeners();
    }

    private void migrateCoreConfigs() {
        migrateConfig("connection.timeoutInSecs", TIMEOUT_KEY);
        migrateConfig("connection.defaultUserAgent", DEFAULT_USER_AGENT_KEY);
        migrateConfig("connection.httpStateEnabled", USE_GLOBAL_HTTP_STATE_KEY);
        migrateConfig("connection.dnsTtlSuccessfulQueries", DNS_TTL_SUCCESSFUL_QUERIES_KEY);

        try {
            List<Object> list = getConfig().getList("connection.securityProtocolsEnabled.protocol");
            if (!list.isEmpty()) {
                persistTlsProtocols(
                        TlsUtils.filterUnsupportedProtocols(
                                list.stream()
                                        .map(Object::toString)
                                        .filter(e -> !e.isEmpty())
                                        .collect(Collectors.toList())));
            }
        } catch (Exception e) {
            LOGGER.warn("An error occurred while migrating old TLS protocols configuration:", e);
        }
        migrateConfig("certificate.allowUnsafeSslRenegotiation", TLS_ALLOW_UNSAFE_RENEGOTIATION);

        migrateConfig("connection.proxyChain.enabled", HTTP_PROXY_ENABLED_KEY);
        migrateConfig("connection.proxyChain.hostName", HTTP_PROXY_HOST_KEY);
        migrateConfig("connection.proxyChain.port", HTTP_PROXY_PORT_KEY);
        migrateConfig("connection.proxyChain.authEnabled", HTTP_PROXY_AUTH_ENABLED_KEY);
        Object promptPassword = getConfig().getProperty("connection.proxyChain.prompt");
        if (promptPassword != null) {
            getConfig()
                    .setProperty(
                            STORE_HTTP_PROXY_PASS_KEY,
                            !Boolean.parseBoolean(promptPassword.toString()));
        }
        migrateConfig("connection.proxyChain.realm", HTTP_PROXY_REALM_KEY);
        migrateConfig("connection.proxyChain.userName", HTTP_PROXY_USERNAME_KEY);
        migrateConfig("connection.proxyChain.password", HTTP_PROXY_PASSWORD_KEY);

        try {
            int migratedExclusions = 0;
            List<HierarchicalConfiguration> exclusions =
                    ((HierarchicalConfiguration) getConfig())
                            .configurationsAt("connection.proxyChain.exclusions.exclusion");
            for (int i = 0; i < exclusions.size(); ++i) {
                String oldConfig = "connection.proxyChain.exclusions.exclusion(" + i + ").";
                String oldName = getString(oldConfig + "name", "");
                if (!oldName.isEmpty()) {
                    String newConfig = HTTP_PROXY_EXCLUSION_KEY + "(" + migratedExclusions + ").";
                    migrateConfig(
                            oldConfig + "enabled", newConfig + HTTP_PROXY_EXCLUSION_ENABLED_KEY);
                    if (!getBoolean(oldConfig + "regex", false)) {
                        oldName = Pattern.quote(oldName);
                    }
                    getConfig().setProperty(newConfig + HTTP_PROXY_EXCLUSION_HOST_KEY, oldName);
                    migratedExclusions++;
                }
            }
            migrateConfig(
                    "connection.proxyChain.confirmRemoveExcludedDomain",
                    HTTP_PROXY_EXCLUSIONS_CONFIRM_REMOVE);
        } catch (Exception e) {
            LOGGER.warn("An error occurred while migrating old proxy exclusions:", e);
        }

        migrateConfig("connection.socksProxy.enabled", SOCKS_PROXY_ENABLED_KEY);
        migrateConfig("connection.socksProxy.host", SOCKS_PROXY_HOST_KEY);
        migrateConfig("connection.socksProxy.port", SOCKS_PROXY_PORT_KEY);
        migrateConfig("connection.socksProxy.version", SOCKS_PROXY_VERSION_KEY);
        migrateConfig("connection.socksProxy.dns", SOCKS_PROXY_DNS_KEY);
        migrateConfig("connection.socksProxy.username", SOCKS_PROXY_USERNAME_KEY);
        migrateConfig("connection.socksProxy.password", SOCKS_PROXY_PASSWORD_KEY);

        ((HierarchicalConfiguration) getConfig()).clearTree("connection");
    }

    private void migrateConfig(String oldConfig, String newConfig) {
        Object oldValue = getConfig().getProperty(oldConfig);
        if (oldValue != null) {
            getConfig().setProperty(newConfig, oldValue);
            getConfig().clearProperty(oldConfig);
        }
    }

    /**
     * Sets the timeout, for reads and connects.
     *
     * @param timeoutInSecs the timeout, in seconds.
     */
    public void setTimeoutInSecs(int timeoutInSecs) {
        setTimeoutInSecsImpl(timeoutInSecs);
        getConfig().setProperty(TIMEOUT_KEY, this.timeoutInSecs);

        notifyChangesListeners();
    }

    private void notifyChangesListeners() {
        changesListeners.forEach(ChangesListener::optionsChanged);
    }

    private void setTimeoutInSecsImpl(int timeoutInSecs) {
        this.timeoutInSecs = timeoutInSecs < 0 ? DEFAULT_TIMEOUT : timeoutInSecs;
    }

    /**
     * Gets the timeout.
     *
     * @return the timeout, in seconds.
     */
    public int getTimeoutInSecs() {
        return timeoutInSecs;
    }

    /**
     * Sets the default user-agent.
     *
     * @param defaultUserAgent the default user-agent, might be {@code null}.
     */
    public void setDefaultUserAgent(String defaultUserAgent) {
        setDefaultUserAgentImpl(defaultUserAgent);
        getConfig().setProperty(DEFAULT_USER_AGENT_KEY, defaultUserAgent);
    }

    private void setDefaultUserAgentImpl(String defaultUserAgent) {
        this.defaultUserAgent = defaultUserAgent;
        HttpRequestHeader.setDefaultUserAgent(defaultUserAgent);
    }

    /**
     * Gets the default user-agent.
     *
     * @return the default user-agent, might be {@code null}.
     */
    public String getDefaultUserAgent() {
        return defaultUserAgent;
    }

    /**
     * Sets whether or not to use the global HTTP state.
     *
     * @param useGlobalHttpState {@code true} if the global HTTP state should be used, {@code false}
     *     otherwise.
     */
    public void setUseGlobalHttpState(boolean useGlobalHttpState) {
        this.useGlobalHttpState = useGlobalHttpState;
        getConfig().setProperty(USE_GLOBAL_HTTP_STATE_KEY, useGlobalHttpState);
    }

    /**
     * Tells whether or not to use global HTTP state.
     *
     * @return {@code true} if the global HTTP state should be used, {@code false} otherwise.
     */
    public boolean isUseGlobalHttpState() {
        return useGlobalHttpState;
    }

    /**
     * Gets the TTL (in seconds) of successful DNS queries.
     *
     * @return the TTL in seconds
     * @see #setDnsTtlSuccessfulQueries(int)
     */
    public int getDnsTtlSuccessfulQueries() {
        return dnsTtlSuccessfulQueries;
    }

    /**
     * Sets the TTL (in seconds) of successful DNS queries.
     *
     * <p>Some values have special meaning:
     *
     * <ul>
     *   <li>Negative number, cache forever;
     *   <li>Zero, disables caching;
     *   <li>Positive number, the number of seconds the successful DNS queries will be cached.
     * </ul>
     *
     * @param ttl the TTL in seconds
     * @see #getDnsTtlSuccessfulQueries()
     */
    public void setDnsTtlSuccessfulQueries(int ttl) {
        dnsTtlSuccessfulQueries = ttl;
        getConfig().setProperty(DNS_TTL_SUCCESSFUL_QUERIES_KEY, ttl);
    }

    /**
     * Sets the SSL/TLS protocols for outgoing connections.
     *
     * @param tlsProtocols the SSL/TLS protocols for outgoing connections.
     * @throws IllegalArgumentException if no protocol is provided or none supported.
     */
    public void setTlsProtocols(List<String> tlsProtocols) {
        this.tlsProtocols = TlsUtils.filterUnsupportedProtocols(tlsProtocols);
        persistTlsProtocols(tlsProtocols);
        applyTlsProtocols();

        notifyChangesListeners();
    }

    private void persistTlsProtocols(List<String> tlsProtocols) {
        ((HierarchicalConfiguration) getConfig()).clearTree(TLS_PROTOCOLS_KEY);
        for (int i = 0; i < tlsProtocols.size(); ++i) {
            String elementBaseKey = TLS_PROTOCOL_KEY + "(" + i + ")";
            getConfig().setProperty(elementBaseKey, tlsProtocols.get(i));
        }
    }

    private void applyTlsProtocols() {
        try {
            SSLConnector.setClientEnabledProtocols(tlsProtocols.toArray(new String[0]));
        } catch (IllegalArgumentException e) {
            LOGGER.warn(
                    "Failed to apply protocols {} falling back to {} caused by: {}",
                    tlsProtocols,
                    TlsUtils.getSupportedProtocols(),
                    e.getMessage());
            tlsProtocols = TlsUtils.getSupportedProtocols();
            SSLConnector.setClientEnabledProtocols(tlsProtocols.toArray(new String[0]));
        }
    }

    /**
     * Gets the SSL/TLS protocols for outgoing connections.
     *
     * @return the SSL/TLS protocols for outgoing connections.
     */
    public List<String> getTlsProtocols() {
        return tlsProtocols;
    }

    /**
     * Tells whether or not the unsafe SSL/TLS renegotiation is enabled.
     *
     * @return {@code true} if the unsafe SSL/TLS renegotiation is enabled, {@code false} otherwise.
     */
    public boolean isAllowUnsafeRenegotiation() {
        return allowUnsafeRenegotiation;
    }

    /**
     * Sets whether or not the unsafe SSL renegotiation is enabled.
     *
     * <p>Calling this method changes the system property
     * "sun.security.ssl.allowUnsafeRenegotiation" and "com.ibm.jsse2.renegotiate". It must be set
     * before establishing any SSL/TLS connection. Further changes after establishing a connection
     * will have no effect on the renegotiation but the value will be saved and restored next time
     * ZAP is restarted.
     *
     * @param allow {@code true} if the unsafe SSL/TLS renegotiation should be enabled, {@code
     *     false} otherwise.
     */
    public void setAllowUnsafeRenegotiation(boolean allow) {
        if (allowUnsafeRenegotiation != allow) {
            allowUnsafeRenegotiation = allow;

            setAllowUnsafeRenegotiationSystemProperty(allowUnsafeRenegotiation);
            getConfig().setProperty(TLS_ALLOW_UNSAFE_RENEGOTIATION, allowUnsafeRenegotiation);
        }
    }

    /**
     * Sets the given value to system property "sun.security.ssl.allowUnsafeRenegotiation" and sets
     * the appropriate value to system property "com.ibm.jsse2.renegotiate", which enables or not
     * the unsafe SSL/TLS renegotiation.
     *
     * <p>It must be set before establishing any SSL connection. Further changes after establishing
     * a SSL connection will have no effect.
     *
     * @param allow the value to set to the property
     */
    private static void setAllowUnsafeRenegotiationSystemProperty(boolean allow) {
        String ibmSystemPropertyValue;
        if (allow) {
            LOGGER.info("Unsafe SSL/TLS renegotiation enabled.");
            ibmSystemPropertyValue = "ALL";
        } else {
            LOGGER.info("Unsafe SSL/TLS renegotiation disabled.");
            ibmSystemPropertyValue = "NONE";
        }
        System.setProperty("com.ibm.jsse2.renegotiate", ibmSystemPropertyValue);
        System.setProperty("sun.security.ssl.allowUnsafeRenegotiation", String.valueOf(allow));
    }

    private void parseHttpProxyOptions() {

        httpProxyEnabled = getBoolean(HTTP_PROXY_ENABLED_KEY, false);
        httpProxyAuthEnabled = getBoolean(HTTP_PROXY_AUTH_ENABLED_KEY, false);
        storeHttpProxyPass = getBoolean(STORE_HTTP_PROXY_PASS_KEY, DEFAULT_STORE_HTTP_PROXY_PASS);

        PasswordAuthentication passwordAuthentication =
                new PasswordAuthentication(
                        getString(HTTP_PROXY_USERNAME_KEY, ""),
                        getString(HTTP_PROXY_PASSWORD_KEY, "").toCharArray());
        String host = getString(HTTP_PROXY_HOST_KEY, DEFAULT_HTTP_PROXY.getHost());
        if (host.isEmpty()) {
            host = DEFAULT_HTTP_PROXY.getHost();
        }
        httpProxy =
                new HttpProxy(
                        host,
                        parsePort(
                                getConfig().getString(HTTP_PROXY_PORT_KEY),
                                DEFAULT_HTTP_PROXY.getPort()),
                        getString(HTTP_PROXY_REALM_KEY, DEFAULT_HTTP_PROXY.getRealm()),
                        passwordAuthentication);

        List<HierarchicalConfiguration> fields =
                ((HierarchicalConfiguration) getConfig())
                        .configurationsAt(HTTP_PROXY_EXCLUSION_KEY);
        httpProxyExclusions = new ArrayList<>(fields.size());
        for (HierarchicalConfiguration sub : fields) {
            try {
                Pattern pattern =
                        createHttpProxyExclusionPattern(
                                sub.getString(HTTP_PROXY_EXCLUSION_HOST_KEY, ""));
                if (pattern != null) {
                    httpProxyExclusions.add(
                            new HttpProxyExclusion(
                                    pattern,
                                    sub.getBoolean(HTTP_PROXY_EXCLUSION_ENABLED_KEY, true)));
                }
            } catch (ConversionException e) {
                LOGGER.warn("An error occurred while reading a HTTP proxy exclusion:", e);
            }
        }
        confirmRemoveHttpProxyExclusion = getBoolean(HTTP_PROXY_EXCLUSIONS_CONFIRM_REMOVE, true);
    }

    private static int parsePort(String value, int defaultPort) {
        if (value == null || value.isEmpty()) {
            return defaultPort;
        }

        int port;
        try {
            port = Integer.parseInt(value);
        } catch (NumberFormatException e) {
            LOGGER.warn("Failed to parse the port: {}", value, e);
            return defaultPort;
        }

        if (port > 0 && port <= 65535) {
            return port;
        }

        LOGGER.warn("Invalid port: {}", value);
        return defaultPort;
    }

    /**
     * Tells whether or not to HTTP proxy should be used for the given host.
     *
     * @param host the host to check.
     * @return {@code true} if the HTTP proxy should be used, {@code false} otherwise.
     */
    public boolean isUseHttpProxy(String host) {
        if (!httpProxyEnabled || host == null || host.isEmpty()) {
            return false;
        }

        for (HttpProxyExclusion exclusion : httpProxyExclusions) {
            if (exclusion.test(host)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Tells whether or not the HTTP proxy is enabled.
     *
     * @return {@code true} if the HTTP proxy is enabled, {@code false} otherwise.
     */
    public boolean isHttpProxyEnabled() {
        return httpProxyEnabled;
    }

    /**
     * Sets whether or not the HTTP proxy is enabled.
     *
     * @param enabled {@code true} if the HTTP proxy should be enabled, {@code false} otherwise.
     */
    public void setHttpProxyEnabled(boolean enabled) {
        this.httpProxyEnabled = enabled;
        getConfig().setProperty(HTTP_PROXY_ENABLED_KEY, enabled);
    }

    /**
     * Tells whether or not the HTTP proxy authentication is enabled.
     *
     * @return {@code true} if the HTTP proxy authentication is enabled, {@code false} otherwise.
     */
    public boolean isHttpProxyAuthEnabled() {
        return httpProxyAuthEnabled;
    }

    /**
     * Sets whether or not the HTTP proxy authentication is enabled.
     *
     * @param enabled {@code true} if the HTTP proxy authentication should be enabled, {@code false}
     *     otherwise.
     */
    public void setHttpProxyAuthEnabled(boolean enabled) {
        this.httpProxyAuthEnabled = enabled;
        getConfig().setProperty(HTTP_PROXY_AUTH_ENABLED_KEY, enabled);
    }

    /**
     * Tells whether or not the HTTP proxy password is stored in the configuration file.
     *
     * @return {@code true} if the HTTP proxy password is stored in the configuration file, {@code
     *     false} otherwise.
     */
    public boolean isStoreHttpProxyPass() {
        return storeHttpProxyPass;
    }

    /**
     * Sets whether or not the HTTP proxy password should be stored in the configuration file.
     *
     * @param store {@code true} if the HTTP proxy password should be stored in the configuration
     *     file, {@code false} otherwise.
     */
    public void setStoreHttpProxyPass(boolean store) {
        this.storeHttpProxyPass = store;

        getConfig().setProperty(STORE_HTTP_PROXY_PASS_KEY, store);
        storeHttpProxyPass();
    }

    private void storeHttpProxyPass() {
        String password =
                storeHttpProxyPass
                        ? new String(httpProxy.getPasswordAuthentication().getPassword())
                        : "";
        getConfig().setProperty(HTTP_PROXY_PASSWORD_KEY, password);
    }

    /**
     * Gets the HTTP proxy.
     *
     * @return the HTTP proxy, never {@code null}.
     */
    public HttpProxy getHttpProxy() {
        return httpProxy;
    }

    /**
     * Sets the HTTP proxy.
     *
     * @param httpProxy the HTTP proxy.
     * @throws NullPointerException if the given {@code httpProxy} is {@code null}.
     */
    public void setHttpProxy(HttpProxy httpProxy) {
        if (this.httpProxy.equals(httpProxy)) {
            return;
        }

        this.httpProxy = Objects.requireNonNull(httpProxy);

        getConfig().setProperty(HTTP_PROXY_HOST_KEY, httpProxy.getHost());
        getConfig().setProperty(HTTP_PROXY_PORT_KEY, httpProxy.getPort());
        getConfig().setProperty(HTTP_PROXY_REALM_KEY, httpProxy.getRealm());
        getConfig()
                .setProperty(
                        HTTP_PROXY_USERNAME_KEY,
                        httpProxy.getPasswordAuthentication().getUserName());
        storeHttpProxyPass();
    }

    /**
     * Adds the given HTTP proxy exclusion.
     *
     * @param httpProxyExclusion the HTTP proxy exclusion.
     * @throws NullPointerException if the given HTTP proxy exclusion is {@code null}.
     */
    public void addHttpProxyExclusion(HttpProxyExclusion httpProxyExclusion) {
        Objects.requireNonNull(httpProxyExclusion);
        httpProxyExclusions.add(httpProxyExclusion);
        persistHttpProxyExclusions();
    }

    private void persistHttpProxyExclusions() {
        ((HierarchicalConfiguration) getConfig()).clearTree(HTTP_PROXY_EXCLUSION_KEY);

        for (int i = 0, size = httpProxyExclusions.size(); i < size; ++i) {
            String elementBaseKey = HTTP_PROXY_EXCLUSION_KEY + "(" + i + ").";
            HttpProxyExclusion httpProxyExclusion = httpProxyExclusions.get(i);

            getConfig()
                    .setProperty(
                            elementBaseKey + HTTP_PROXY_EXCLUSION_HOST_KEY,
                            httpProxyExclusion.getHost().pattern());
            getConfig()
                    .setProperty(
                            elementBaseKey + HTTP_PROXY_EXCLUSION_ENABLED_KEY,
                            httpProxyExclusion.isEnabled());
        }
    }

    /**
     * Sets whether or not the HTTP proxy exclusion with the given host should be enabled.
     *
     * @param host the value of the host.
     * @param enabled {@code true} if the HTTP proxy exclusion should be enabled, {@code false}
     *     otherwise.
     * @return {@code true} if the HTTP proxy exclusion was changed, {@code false} otherwise.
     * @throws NullPointerException if the given host is {@code null}.
     */
    public boolean setHttpProxyExclusionEnabled(String host, boolean enabled) {
        Objects.requireNonNull(host);
        for (Iterator<HttpProxyExclusion> it = httpProxyExclusions.iterator(); it.hasNext(); ) {
            HttpProxyExclusion httpProxyExclusion = it.next();
            if (host.equals(httpProxyExclusion.getHost().pattern())) {
                httpProxyExclusion.setEnabled(enabled);
                persistHttpProxyExclusions();
                return true;
            }
        }
        return false;
    }

    /**
     * Removes a HTTP proxy exclusion.
     *
     * @param host the value of the host.
     * @return {@code true} if the HTTP proxy exclusion was removed, {@code false} otherwise.
     */
    public boolean removeHttpProxyExclusion(String host) {
        Objects.requireNonNull(host);
        for (Iterator<HttpProxyExclusion> it = httpProxyExclusions.iterator(); it.hasNext(); ) {
            if (host.equals(it.next().getHost().pattern())) {
                it.remove();
                persistHttpProxyExclusions();
                return true;
            }
        }
        return false;
    }

    /**
     * Sets the HTTP proxy exclusions.
     *
     * @param httpProxyExclusions the HTTP proxy exclusions.
     * @throws NullPointerException if the given list is {@code null}.
     */
    public void setHttpProxyExclusions(List<HttpProxyExclusion> httpProxyExclusions) {
        Objects.requireNonNull(httpProxyExclusions);

        this.httpProxyExclusions = new ArrayList<>(httpProxyExclusions);
        persistHttpProxyExclusions();
    }

    /**
     * Gets all the HTTP proxy exclusions.
     *
     * @return the list of HTTP proxy exclusions, never {@code null}.
     */
    public List<HttpProxyExclusion> getHttpProxyExclusions() {
        return httpProxyExclusions;
    }

    /**
     * Sets whether or not the removal of a HTTP proxy exclusion needs confirmation.
     *
     * @param confirmRemove {@code true} if the removal needs confirmation, {@code false} otherwise.
     */
    public void setConfirmRemoveHttpProxyExclusion(boolean confirmRemove) {
        this.confirmRemoveHttpProxyExclusion = confirmRemove;
        getConfig()
                .setProperty(HTTP_PROXY_EXCLUSIONS_CONFIRM_REMOVE, confirmRemoveHttpProxyExclusion);
    }

    /**
     * Tells whether or not the removal of a HTTP proxy exclusion needs confirmation.
     *
     * @return {@code true} if the removal needs confirmation, {@code false} otherwise.
     */
    public boolean isConfirmRemoveHttpProxyExclusion() {
        return confirmRemoveHttpProxyExclusion;
    }

    private static Pattern createHttpProxyExclusionPattern(String value) {
        try {
            return HttpProxyExclusion.createHostPattern(value);
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Ignoring invalid HTTP proxy exclusion pattern:", e);
            return null;
        }
    }

    private void parseSocksProxyOptions() {
        String host = System.getProperty("socksProxyHost");
        int port;
        String version;
        boolean useDns = getBoolean(SOCKS_PROXY_DNS_KEY, DEFAULT_SOCKS_PROXY.isUseDns());

        if (host != null && !host.isEmpty()) {
            port = parseSocksPort(System.getProperty("socksProxyPort"));
            version = System.getProperty("socksProxyVersion");

            socksProxyEnabled = true;
        } else {
            host = getString(SOCKS_PROXY_HOST_KEY, DEFAULT_SOCKS_PROXY.getHost());
            if (host.isEmpty()) {
                host = DEFAULT_SOCKS_PROXY.getHost();
            }
            port = parseSocksPort(getConfig().getString(SOCKS_PROXY_PORT_KEY));
            version =
                    getString(
                            SOCKS_PROXY_VERSION_KEY,
                            String.valueOf(DEFAULT_SOCKS_PROXY.getVersion().number()));

            socksProxyEnabled = getBoolean(SOCKS_PROXY_ENABLED_KEY, false);
        }

        PasswordAuthentication passwordAuthentication =
                new PasswordAuthentication(
                        getString(SOCKS_PROXY_USERNAME_KEY, ""),
                        getString(SOCKS_PROXY_PASSWORD_KEY, "").toCharArray());
        socksProxy =
                new SocksProxy(
                        host,
                        port,
                        SocksProxy.Version.from(version),
                        useDns,
                        passwordAuthentication);
        applySocksProxy();
    }

    private static int parseSocksPort(String value) {
        return parsePort(value, DEFAULT_SOCKS_PROXY.getPort());
    }

    /**
     * Applies the SOCKS proxy configuration to the SOCKS system properties.
     *
     * <p>If the SOCKS proxy is not in use (i.e. {@link #useSocksProxy} is {@code false}) the system
     * properties are cleared.
     */
    private void applySocksProxy() {
        String host = "";
        String port = "";
        String version = "";
        if (socksProxyEnabled) {
            host = socksProxy.getHost();
            port = Integer.toString(socksProxy.getPort());
            version = Integer.toString(socksProxy.getVersion().number());
        }
        System.setProperty("socksProxyHost", host);
        System.setProperty("socksProxyPort", port);
        System.setProperty("socksProxyVersion", version);
    }

    /**
     * Tells whether or not the given host should be resolved.
     *
     * <p>The names should not be resolved when ZAP is configured to use a SOCKSv5 proxy and rely on
     * it for resolution.
     *
     * @param host the name to check.
     * @return {@code true} if the given {@code host} should be resolved, {@code false} otherwise.
     */
    public boolean shouldResolveRemoteHostname(String host) {
        if (!socksProxyEnabled
                || !socksProxy.isUseDns()
                || socksProxy.getVersion() != SocksProxy.Version.SOCKS5) {
            return true;
        }
        return LOOPBACK_PATTERN.matcher(host).matches();
    }

    /**
     * Tells whether or not the SOCKS proxy is enabled.
     *
     * @return {@code true} if the SOCKS proxy is enabled, {@code false} otherwise.
     */
    public boolean isSocksProxyEnabled() {
        return socksProxyEnabled;
    }

    /**
     * Sets whether or not the SOCKS proxy is enabled.
     *
     * @param enabled {@code true} if the SOCKS proxy should be enabled, {@code false} otherwise.
     */
    public void setSocksProxyEnabled(boolean enabled) {
        this.socksProxyEnabled = enabled;

        getConfig().setProperty(SOCKS_PROXY_ENABLED_KEY, enabled);

        applySocksProxy();
    }

    /**
     * Gets the SOCKS proxy.
     *
     * @return the SOCKS proxy, never {@code null}.
     */
    public SocksProxy getSocksProxy() {
        return socksProxy;
    }

    /**
     * Sets the SOCKS proxy.
     *
     * @param socksProxy the SOCKS proxy.
     * @throws NullPointerException if the given {@code socksProxy} is {@code null}.
     */
    public void setSocksProxy(SocksProxy socksProxy) {
        if (this.socksProxy.equals(socksProxy)) {
            return;
        }

        this.socksProxy = Objects.requireNonNull(socksProxy);

        getConfig().setProperty(SOCKS_PROXY_HOST_KEY, socksProxy.getHost());
        getConfig().setProperty(SOCKS_PROXY_PORT_KEY, socksProxy.getPort());
        getConfig().setProperty(SOCKS_PROXY_VERSION_KEY, socksProxy.getVersion().number());
        getConfig().setProperty(SOCKS_PROXY_DNS_KEY, socksProxy.isUseDns());
        PasswordAuthentication auth = socksProxy.getPasswordAuthentication();
        getConfig().setProperty(SOCKS_PROXY_USERNAME_KEY, auth.getUserName());
        getConfig().setProperty(SOCKS_PROXY_PASSWORD_KEY, new String(auth.getPassword()));

        if (socksProxyEnabled) {
            applySocksProxy();
        }
    }

    public void addChangesListener(ChangesListener listener) {
        Objects.requireNonNull(listener);
        changesListeners.add(listener);
    }

    public interface ChangesListener {

        void optionsChanged();
    }
}
