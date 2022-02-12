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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.apache.commons.configuration.ConversionException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.network.internal.TlsUtils;
import org.zaproxy.addon.network.internal.server.http.Alias;
import org.zaproxy.addon.network.internal.server.http.LocalServerConfig;
import org.zaproxy.addon.network.internal.server.http.LocalServerConfig.ServerMode;
import org.zaproxy.addon.network.internal.server.http.PassThrough;
import org.zaproxy.zap.common.VersionedAbstractParam;

/** The options related to local servers/proxies. */
public class LocalServersOptions extends VersionedAbstractParam {

    private static final Logger LOGGER = LogManager.getLogger(LocalServersOptions.class);
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

    private static final String BASE_KEY = "network.localServers";

    /**
     * The configuration key for the version of the configurations.
     *
     * @see #CURRENT_CONFIG_VERSION
     */
    private static final String CONFIG_VERSION_KEY = BASE_KEY + VERSION_ATTRIBUTE;

    private static final String MAIN_PROXY_BASE_KEY = BASE_KEY + ".mainProxy";
    private static final String SERVERS_BASE_KEY = BASE_KEY + ".servers";
    private static final String ALL_SERVERS_KEY = SERVERS_BASE_KEY + ".server";
    private static final String SERVER_PROXY = "proxy";
    private static final String SERVER_API = "api";
    private static final String SERVER_ADDRESS = "address";
    private static final String SERVER_PORT = "port";
    private static final String SERVER_TLS_PROTOCOLS = "tlsProtocols";
    private static final String SERVER_TLS_PROTOCOL = "protocol";
    private static final String SERVER_BEHIND_NAT = "behindNat";
    private static final String SERVER_REMOVE_ACCEPT_ENCODING = "removeAcceptEncoding";
    private static final String SERVER_DECODE_RESPONSE = "decodeResponse";
    private static final String SERVER_ENABLED = "enabled";
    private static final String CONFIRM_REMOVE_SERVER = SERVERS_BASE_KEY + ".confirmRemove";

    private static final String ALIASES_BASE_KEY = BASE_KEY + ".aliases";
    private static final String ALL_ALIASES_KEY = ALIASES_BASE_KEY + ".alias";
    private static final String ALIAS_ENABLED = "enabled";
    private static final String ALIAS_NAME = "name";
    private static final String CONFIRM_REMOVE_ALIAS = ALIASES_BASE_KEY + ".confirmRemove";

    private static final String PASS_THROUGHS_BASE_KEY = BASE_KEY + ".passThroughs";
    private static final String ALL_PASS_THROUGHS_KEY = PASS_THROUGHS_BASE_KEY + ".passThrough";
    private static final String PASS_THROUGH_ENABLED = "enabled";
    private static final String PASS_THROUGH_AUTHORITY = "authority";
    private static final String CONFIRM_REMOVE_PASS_THROUGH =
            PASS_THROUGHS_BASE_KEY + ".confirmRemove";

    private List<Alias> aliases = new ArrayList<>();
    private boolean confirmRemoveAlias = true;
    private List<PassThrough> passThroughs = new ArrayList<>();
    private boolean confirmRemovePassThrough = true;
    private LocalServerConfig mainProxy = new LocalServerConfig();
    private List<LocalServerConfig> servers = Collections.emptyList();
    private boolean confirmRemoveServer = true;
    private List<ServersChangedListener> serversChangedListener = new ArrayList<>(2);

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

        List<HierarchicalConfiguration> fields =
                ((HierarchicalConfiguration) getConfig()).configurationsAt(ALL_ALIASES_KEY);
        aliases = new ArrayList<>(fields.size());
        for (HierarchicalConfiguration sub : fields) {
            try {
                String value = sub.getString(ALIAS_NAME, "");
                if (value != null && !value.isEmpty()) {
                    boolean enabled = sub.getBoolean(ALIAS_ENABLED, true);
                    aliases.add(new Alias(value, enabled));
                }
            } catch (ConversionException e) {
                LOGGER.warn("An error occurred while reading an alias:", e);
            }
        }
        confirmRemoveAlias = getBoolean(CONFIRM_REMOVE_ALIAS, true);

        fields = ((HierarchicalConfiguration) getConfig()).configurationsAt(ALL_PASS_THROUGHS_KEY);
        passThroughs = new ArrayList<>(fields.size());
        for (HierarchicalConfiguration sub : fields) {
            try {
                String value = sub.getString(PASS_THROUGH_AUTHORITY, "");
                Pattern pattern = createPassThroughPattern(value);
                if (pattern != null) {
                    boolean enabled = sub.getBoolean(PASS_THROUGH_ENABLED, true);
                    passThroughs.add(new PassThrough(pattern, enabled));
                }
            } catch (ConversionException e) {
                LOGGER.warn("An error occurred while reading a pass-through:", e);
            }
        }
        confirmRemovePassThrough = getBoolean(CONFIRM_REMOVE_PASS_THROUGH, true);

        readMainProxyAndServers();
    }

    /**
     * Adds the given alias.
     *
     * @param alias the alias.
     * @throws NullPointerException if the given alias is {@code null}.
     */
    public void addAlias(Alias alias) {
        Objects.requireNonNull(alias);
        aliases.add(alias);
        persistAliases();
    }

    private void persistAliases() {
        ((HierarchicalConfiguration) getConfig()).clearTree(ALL_ALIASES_KEY);

        for (int i = 0, size = aliases.size(); i < size; ++i) {
            String elementBaseKey = ALL_ALIASES_KEY + "(" + i + ").";
            Alias alias = aliases.get(i);

            getConfig().setProperty(elementBaseKey + ALIAS_NAME, alias.getName());
            getConfig().setProperty(elementBaseKey + ALIAS_ENABLED, alias.isEnabled());
        }
    }

    /**
     * Sets whether or not the alias with the given name should be enabled.
     *
     * @param name the name of the alias.
     * @param enabled {@code true} if the alias should be enabled, {@code false} otherwise.
     * @return {@code true} if the alias was changed, {@code false} otherwise.
     * @throws NullPointerException if the given name is {@code null}.
     */
    public boolean setAliasEnabled(String name, boolean enabled) {
        Objects.requireNonNull(name);
        for (Iterator<Alias> it = aliases.iterator(); it.hasNext(); ) {
            Alias alias = it.next();
            if (name.equals(alias.getName())) {
                alias.setEnabled(enabled);
                persistAliases();
                return true;
            }
        }
        return false;
    }

    /**
     * Removes an alias.
     *
     * @param name the name of the alias.
     * @return {@code true} if the alias was removed, {@code false} otherwise.
     */
    public boolean removeAlias(String name) {
        Objects.requireNonNull(name);
        for (Iterator<Alias> it = aliases.iterator(); it.hasNext(); ) {
            if (name.equals(it.next().getName())) {
                it.remove();
                persistAliases();
                return true;
            }
        }
        return false;
    }

    /**
     * Sets the aliases.
     *
     * @param aliases the aliases.
     * @throws NullPointerException if the given list is {@code null}.
     */
    public void setAliases(List<Alias> aliases) {
        Objects.requireNonNull(aliases);

        this.aliases = new ArrayList<>(aliases);
        persistAliases();
    }

    /**
     * Gets the aliases.
     *
     * @return the aliases, never {@code null}.
     */
    public List<Alias> getAliases() {
        return aliases;
    }

    /**
     * Sets whether or not the removal of an alias needs confirmation.
     *
     * @param confirmRemove {@code true} if the removal needs confirmation, {@code false} otherwise.
     */
    public void setConfirmRemoveAlias(boolean confirmRemove) {
        this.confirmRemoveAlias = confirmRemove;
        getConfig().setProperty(CONFIRM_REMOVE_ALIAS, confirmRemoveAlias);
    }

    /**
     * Tells whether or not the removal of an alias needs confirmation.
     *
     * @return {@code true} if the removal needs confirmation, {@code false} otherwise.
     */
    public boolean isConfirmRemoveAlias() {
        return confirmRemoveAlias;
    }

    /**
     * Adds the given pass-through.
     *
     * @param passThrough the pass-through.
     * @throws NullPointerException if the given pass-through is {@code null}.
     */
    public void addPassThrough(PassThrough passThrough) {
        Objects.requireNonNull(passThrough);
        passThroughs.add(passThrough);
        persistPassThroughs();
    }

    private void persistPassThroughs() {
        ((HierarchicalConfiguration) getConfig()).clearTree(ALL_PASS_THROUGHS_KEY);

        for (int i = 0, size = passThroughs.size(); i < size; ++i) {
            String elementBaseKey = ALL_PASS_THROUGHS_KEY + "(" + i + ").";
            PassThrough passThrough = passThroughs.get(i);

            getConfig()
                    .setProperty(
                            elementBaseKey + PASS_THROUGH_AUTHORITY,
                            passThrough.getAuthority().pattern());
            getConfig().setProperty(elementBaseKey + PASS_THROUGH_ENABLED, passThrough.isEnabled());
        }
    }

    /**
     * Sets whether or not the pass-through with the given authority should be enabled.
     *
     * @param authority the value of the authority.
     * @param enabled {@code true} if the pass-through should be enabled, {@code false} otherwise.
     * @return {@code true} if the pass-through was changed, {@code false} otherwise.
     * @throws NullPointerException if the given authority is {@code null}.
     */
    public boolean setPassThroughEnabled(String authority, boolean enabled) {
        Objects.requireNonNull(authority);
        for (Iterator<PassThrough> it = passThroughs.iterator(); it.hasNext(); ) {
            PassThrough passThrough = it.next();
            if (authority.equals(passThrough.getAuthority().pattern())) {
                passThrough.setEnabled(enabled);
                persistPassThroughs();
                return true;
            }
        }
        return false;
    }

    /**
     * Removes a pass-through.
     *
     * @param authority the value of the authority.
     * @return {@code true} if the pass-through was removed, {@code false} otherwise.
     */
    public boolean removePassThrough(String authority) {
        Objects.requireNonNull(authority);
        for (Iterator<PassThrough> it = passThroughs.iterator(); it.hasNext(); ) {
            if (authority.equals(it.next().getAuthority().pattern())) {
                it.remove();
                persistPassThroughs();
                return true;
            }
        }
        return false;
    }

    /**
     * Sets the pass-through.
     *
     * @param passThroughs the pass-through.
     * @throws NullPointerException if the given list is {@code null}.
     */
    public void setPassThroughs(List<PassThrough> passThroughs) {
        this.passThroughs = Objects.requireNonNull(passThroughs);

        this.passThroughs = new ArrayList<>(passThroughs);
        persistPassThroughs();
    }

    /**
     * Gets all the pass-throughs.
     *
     * @return the list of pass-throughs, never {@code null}.
     */
    public List<PassThrough> getPassThroughs() {
        return passThroughs;
    }

    /**
     * Sets whether or not the removal of a pass-through needs confirmation.
     *
     * @param confirmRemove {@code true} if the removal needs confirmation, {@code false} otherwise.
     */
    public void setConfirmRemovePassThrough(boolean confirmRemove) {
        this.confirmRemovePassThrough = confirmRemove;
        getConfig().setProperty(CONFIRM_REMOVE_PASS_THROUGH, confirmRemovePassThrough);
    }

    /**
     * Tells whether or not the removal of a pass-through needs confirmation.
     *
     * @return {@code true} if the removal needs confirmation, {@code false} otherwise.
     */
    public boolean isConfirmRemovePassThrough() {
        return confirmRemovePassThrough;
    }

    private static Pattern createPassThroughPattern(String value) {
        try {
            return PassThrough.createAuthorityPattern(value);
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Ignoring invalid pass-through pattern:", e);
            return null;
        }
    }

    private void readMainProxyAndServers() {
        if (getConfig().containsKey(MAIN_PROXY_BASE_KEY + "." + SERVER_ADDRESS)) {
            mainProxy =
                    readServerConfig(
                            ((HierarchicalConfiguration) getConfig())
                                    .configurationAt(MAIN_PROXY_BASE_KEY));
        }
        if (mainProxy == null) {
            mainProxy = new LocalServerConfig();
        } else if (!mainProxy.getMode().hasProxy()) {
            mainProxy.setMode(ServerMode.API_AND_PROXY);
        }
        mainProxy.setEnabled(true);

        List<HierarchicalConfiguration> fields =
                ((HierarchicalConfiguration) getConfig()).configurationsAt(ALL_SERVERS_KEY);
        servers = new ArrayList<>(fields.size());
        for (HierarchicalConfiguration sub : fields) {
            LocalServerConfig serverConfig = readServerConfig(sub);
            if (serverConfig != null) {
                servers.add(serverConfig);
            }
        }
        confirmRemoveServer = getBoolean(CONFIRM_REMOVE_SERVER, true);

        Set<String> addresses = new HashSet<>();
        addresses.add(serverAddress(mainProxy));

        for (Iterator<LocalServerConfig> it = servers.iterator(); it.hasNext(); ) {
            LocalServerConfig server = it.next();
            String serverAddress = serverAddress(server);
            if (!addresses.add(serverAddress)) {
                it.remove();
                LOGGER.warn("Discarding server with duplicated address/port: {}", serverAddress);
            }
        }
    }

    private static String serverAddress(LocalServerConfig server) {
        return server.getAddress() + ":" + server.getPort();
    }

    private static LocalServerConfig readServerConfig(HierarchicalConfiguration config) {
        try {
            LocalServerConfig serverConfig = new LocalServerConfig();
            serverConfig.setAddress(
                    config.getString(SERVER_ADDRESS, LocalServerConfig.DEFAULT_ADDRESS));
            serverConfig.setPort(config.getInt(SERVER_PORT, LocalServerConfig.DEFAULT_PORT));
            boolean proxy = config.getBoolean(SERVER_PROXY, true);
            boolean api = config.getBoolean(SERVER_API, true);
            serverConfig.setMode(
                    proxy && api
                            ? ServerMode.API_AND_PROXY
                            : proxy ? ServerMode.PROXY : ServerMode.API);
            List<String> protocols =
                    config.getList(SERVER_TLS_PROTOCOLS + "." + SERVER_TLS_PROTOCOL).stream()
                            .map(Object::toString)
                            .collect(Collectors.toList());
            if (protocols.isEmpty()) {
                protocols = TlsUtils.getSupportedProtocols();
            }
            try {
                serverConfig.setTlsProtocols(protocols);
            } catch (Exception e) {
                LOGGER.warn("An error occurred while setting TLS protocols:", e);
                serverConfig.setTlsProtocols(TlsUtils.getSupportedProtocols());
            }
            serverConfig.setBehindNat(config.getBoolean(SERVER_BEHIND_NAT, false));
            serverConfig.setRemoveAcceptEncoding(
                    config.getBoolean(SERVER_REMOVE_ACCEPT_ENCODING, true));
            serverConfig.setDecodeResponse(config.getBoolean(SERVER_DECODE_RESPONSE, true));
            serverConfig.setEnabled(config.getBoolean(SERVER_ENABLED, true));
            return serverConfig;
        } catch (Exception e) {
            LOGGER.warn("An error occurred while reading a server configuration:", e);
        }
        return null;
    }

    private void persistServerConfig(String baseKey, LocalServerConfig serverConfig) {
        String baseKeyDot = baseKey + ".";
        getConfig().setProperty(baseKeyDot + SERVER_ENABLED, serverConfig.isEnabled());

        getConfig().setProperty(baseKeyDot + SERVER_PROXY, serverConfig.getMode().hasProxy());
        getConfig().setProperty(baseKeyDot + SERVER_API, serverConfig.getMode().hasApi());

        getConfig().setProperty(baseKeyDot + SERVER_ADDRESS, serverConfig.getAddress());
        getConfig().setProperty(baseKeyDot + SERVER_PORT, serverConfig.getPort());

        String protocolsBaseKey = baseKeyDot + SERVER_TLS_PROTOCOLS;
        ((HierarchicalConfiguration) getConfig()).clearTree(protocolsBaseKey);
        for (int i = 0; i < serverConfig.getTlsProtocols().size(); ++i) {
            String elementBaseKey = protocolsBaseKey + "." + SERVER_TLS_PROTOCOL + "(" + i + ")";
            getConfig().setProperty(elementBaseKey, serverConfig.getTlsProtocols().get(i));
        }

        getConfig().setProperty(baseKeyDot + SERVER_BEHIND_NAT, serverConfig.isBehindNat());
        getConfig()
                .setProperty(
                        baseKeyDot + SERVER_REMOVE_ACCEPT_ENCODING,
                        serverConfig.isRemoveAcceptEncoding());
        getConfig()
                .setProperty(baseKeyDot + SERVER_DECODE_RESPONSE, serverConfig.isDecodeResponse());
    }

    /**
     * Gets the main proxy.
     *
     * @return the main proxy, never {@code null}.
     */
    public LocalServerConfig getMainProxy() {
        return mainProxy;
    }

    /**
     * Sets the main proxy.
     *
     * <p>The main proxy is always persisted enabled and having a proxy (i.e. server mode not {@code
     * API}). The proxy is expected to have a unique address and port.
     *
     * @param mainProxy the main proxy.
     * @throws NullPointerException if the given proxy is {@code null}.
     */
    public void setMainProxy(LocalServerConfig mainProxy) {
        this.mainProxy = Objects.requireNonNull(mainProxy);
        mainProxy.setEnabled(true);
        if (!mainProxy.getMode().hasProxy()) {
            mainProxy.setMode(ServerMode.API_AND_PROXY);
        }

        persistServerConfig(MAIN_PROXY_BASE_KEY, mainProxy);

        serversChangedListener.forEach(e -> e.mainProxySet(mainProxy));
    }

    /**
     * Adds the given server.
     *
     * <p>The server is expected to have a unique address and port.
     *
     * @param server the server.
     * @throws NullPointerException if the given server is {@code null}.
     */
    public void addServer(LocalServerConfig server) {
        Objects.requireNonNull(server);
        servers.add(server);
        persistServers();

        serversChangedListener.forEach(e -> e.serverAdded(server));
    }

    private void persistServers() {
        ((HierarchicalConfiguration) getConfig()).clearTree(ALL_SERVERS_KEY);

        for (int i = 0, size = servers.size(); i < size; ++i) {
            String baseKey = ALL_SERVERS_KEY + "(" + i + ")";
            LocalServerConfig server = servers.get(i);

            persistServerConfig(baseKey, server);
        }
    }

    /**
     * Removes the server with the given address and port.
     *
     * @param address the address of the server.
     * @param port the port of the server.
     * @return {@code true} if the server was removed, {@code false} otherwise.
     * @throws NullPointerException if the given address is {@code null}.
     */
    public boolean removeServer(String address, int port) {
        Objects.requireNonNull(address);
        for (Iterator<LocalServerConfig> it = servers.iterator(); it.hasNext(); ) {
            LocalServerConfig server = it.next();
            if (server.getPort() == port && address.equals(server.getAddress())) {
                it.remove();
                persistServers();

                serversChangedListener.forEach(e -> e.serverRemoved(server));
                return true;
            }
        }
        return false;
    }

    /**
     * Sets the servers.
     *
     * <p>The servers are expected to have a unique address and port.
     *
     * @param servers the servers.
     * @throws NullPointerException if the given list is {@code null}.
     */
    public void setServers(List<LocalServerConfig> servers) {
        Objects.requireNonNull(servers);
        this.servers = new ArrayList<>(servers);

        persistServers();

        serversChangedListener.forEach(e -> e.serversSet(servers));
    }

    /**
     * Gets the servers.
     *
     * @return the servers, never {@code null}.
     */
    public List<LocalServerConfig> getServers() {
        return servers;
    }

    /**
     * Sets whether or not the removal of a server needs confirmation.
     *
     * @param confirmRemove {@code true} if the removal needs confirmation, {@code false} otherwise.
     */
    public void setConfirmRemoveServer(boolean confirmRemove) {
        this.confirmRemoveServer = confirmRemove;
        getConfig().setProperty(CONFIRM_REMOVE_SERVER, confirmRemoveServer);
    }

    /**
     * Tells whether or not the removal of a server needs confirmation.
     *
     * @return {@code true} if the removal needs confirmation, {@code false} otherwise.
     */
    public boolean isConfirmRemoveServer() {
        return confirmRemoveServer;
    }

    private void migrateCoreConfigs() {
        List<String> tlsProtocols = TlsUtils.getSupportedProtocols();
        try {
            tlsProtocols = migrateMainProxy();
        } catch (Exception e) {
            LOGGER.warn("An error occurred while migrating the main proxy:", e);
        }
        ((HierarchicalConfiguration) getConfig()).clearTree("proxy");

        try {
            migrateAdditionalProxies(tlsProtocols);
        } catch (Exception e) {
            LOGGER.warn("An error occurred while migrating the additional proxies:", e);
        }
        ((HierarchicalConfiguration) getConfig()).clearTree("proxies");
    }

    private List<String> migrateMainProxy() {
        if (!getConfig().containsKey("proxy.port")) {
            return TlsUtils.getSupportedProtocols();
        }
        LocalServerConfig config = new LocalServerConfig();
        config.setAddress(getString("proxy.ip", LocalServerConfig.DEFAULT_ADDRESS));
        config.setPort(getInt("proxy.port", LocalServerConfig.DEFAULT_PORT));
        config.setBehindNat(getBoolean("proxy.behindnat", false));
        config.setRemoveAcceptEncoding(getBoolean("proxy.removeUnsupportedEncodings", true));
        config.setDecodeResponse(getBoolean("proxy.decodeGzip", true));

        List<String> tlsProtocols =
                getConfig().getList("proxy.securityProtocolsEnabled.protocol").stream()
                        .map(Object::toString)
                        .collect(Collectors.toList());
        if (tlsProtocols.isEmpty()) {
            tlsProtocols = TlsUtils.getSupportedProtocols();
        }
        config.setTlsProtocols(tlsProtocols);

        setMainProxy(config);
        return tlsProtocols;
    }

    private void migrateAdditionalProxies(List<String> tlsProtocols) {
        String confirmRemoveKey = "proxies.confirmRemoveProxy";
        if (getConfig().containsKey(confirmRemoveKey)) {
            setConfirmRemoveServer(getBoolean(confirmRemoveKey, true));
        }

        List<HierarchicalConfiguration> proxies =
                ((HierarchicalConfiguration) getConfig()).configurationsAt("proxies.all");
        List<LocalServerConfig> additionalServers = new ArrayList<>(proxies.size());
        for (HierarchicalConfiguration sub : proxies) {
            LocalServerConfig config = new LocalServerConfig();
            String address = sub.getString("address", null);
            if (address == null) {
                continue;
            }
            config.setAddress(address);
            config.setPort(sub.getInt("port", LocalServerConfig.DEFAULT_PORT));
            config.setEnabled(sub.getBoolean("enabled", true));
            config.setBehindNat(sub.getBoolean("behindnat", false));
            config.setRemoveAcceptEncoding(sub.getBoolean("remunsupported", true));
            config.setDecodeResponse(sub.getBoolean("decode", true));
            config.setTlsProtocols(tlsProtocols);

            additionalServers.add(config);
        }

        if (!additionalServers.isEmpty()) {
            setServers(additionalServers);
        }
    }

    /**
     * Adds the given listener.
     *
     * @param listener the listener.
     * @throws NullPointerException if the given listener is {@code null}.
     */
    public void addServersChangedListener(ServersChangedListener listener) {
        Objects.requireNonNull(listener);
        this.serversChangedListener.add(listener);
    }

    /** A listener of server changes. */
    public interface ServersChangedListener {

        /**
         * Notifies that the main proxy was set.
         *
         * @param mainProxyConfig the main proxy.
         */
        void mainProxySet(LocalServerConfig mainProxyConfig);

        /**
         * Notifies that a server was added.
         *
         * @param serverConfig the server added.
         */
        void serverAdded(LocalServerConfig serverConfig);

        /**
         * Notifies that a server was removed.
         *
         * @param serverConfig the server removed.
         */
        void serverRemoved(LocalServerConfig serverConfig);

        /**
         * Notifies that servers were set.
         *
         * @param servers the servers set.
         */
        void serversSet(List<LocalServerConfig> servers);
    }
}
