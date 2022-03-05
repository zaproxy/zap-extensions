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
package org.zaproxy.addon.callhome;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import net.sf.json.JSONObject;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.CommandLineListener;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.network.HttpStatusCode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.control.ExtensionFactory;
import org.zaproxy.zap.extension.autoupdate.ExtensionAutoUpdate;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.network.HttpRequestConfig;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class ExtensionCallHome extends ExtensionAdaptor
        implements SessionChangedListener, CommandLineListener {

    // The name is public so that other extensions can access it
    public static final String NAME = "ExtensionCallHome";

    protected static final String PREFIX = "callhome";

    private static final String ZAP_CFU_SERVICE = "https://cfu.zaproxy.org/ZAPcfu";
    private static final String ZAP_NEWS_SERVICE = "https://news.zaproxy.org/ZAPnews";
    private static final String ZAP_TEL_SERVICE = "https://tel.zaproxy.org/ZAPtel";

    private static final String ISSUE_FILE = "/etc/issue";

    private static final Pattern PSCAN_PATTERN = Pattern.compile("stats\\.pscan\\..\\d+\\..*");

    private static final Logger LOGGER = LogManager.getLogger(ExtensionCallHome.class);

    private static final String ZAP_CONTAINER_FILE = "/zap/container";
    private static final String FLATPAK_FILE = "/.flatpak-info";
    public static final String FLATPAK_NAME = "flatpak";
    private static final String SNAP_FILE = "meta/snap.yaml";
    public static final String SNAP_NAME = "snapcraft";
    private static final String HOME_ENVVAR = "HOME";
    public static final String WEBSWING_NAME = "webswing";
    public static final String KALI_NAME = "kali";
    private static final String BACK_BOX_ID = "BackBox";
    private static final HttpRequestConfig HTTP_REQUEST_CONFIG =
            HttpRequestConfig.builder().setFollowRedirects(true).setNotifyListeners(false).build();

    public enum OS {
        WINDOWS,
        LINUX,
        MAC_OS,
        KALI,
        BACK_BOX,
        UNKNOWN;

        @Override
        public String toString() {
            if (MAC_OS.equals(this)) {
                return "MacOS";
            } else if (BACK_BOX.equals(this)) {
                return BACK_BOX_ID;
            }
            // First letter capitalised, rest lower case
            return this.name().substring(0, 1) + this.name().substring(1).toLowerCase(Locale.ROOT);
        }
    }

    private HttpSender httpSender = null;
    private CallHomeParam param;

    private static OS os;
    private static Boolean onBackBox = null;
    private static Boolean inContainer = null;
    private static String containerName;

    private int telIndex = 0;

    private JSONObject lastTelemetryData;

    private LocalDateTime lastSessionCreated;

    private CommandLineArgument[] arguments = new CommandLineArgument[1];
    private static final int ARG_NO_TEL_IDX = 0;

    private OptionsCallHomePanel optionsPanel = null;

    public ExtensionCallHome() {
        super(NAME);
        setI18nPrefix(PREFIX);
        // Just before the Network extension.
        setOrder(Integer.MAX_VALUE - 1);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        extensionHook.addCommandLine(getCommandLineArguments());
        extensionHook.addOptionsParamSet(getParam());
        extensionHook.addSessionListener(this);
        if (getView() != null) {
            extensionHook.getHookView().addOptionPanel(getOptionsPanel());
        }
    }

    @Override
    public void postInit() {
        this.setAutoUpdateSupplier(this::get);
    }

    @Override
    public void unload() {
        this.setAutoUpdateSupplier(null);
    }

    private OptionsCallHomePanel getOptionsPanel() {
        if (optionsPanel == null) {
            optionsPanel = new OptionsCallHomePanel(this);
        }
        return optionsPanel;
    }

    private void setAutoUpdateSupplier(Supplier<ZapXmlConfiguration> supplier) {
        // XXX Change to not use reflection after 2.12.0
        ExtensionAutoUpdate extAu =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutoUpdate.class);
        if (extAu != null) {
            try {
                Method setSupplierMethod =
                        extAu.getClass().getMethod("setCheckForUpdatesSupplier", Supplier.class);
                LOGGER.debug("Setting CheckForUpdates supplier: {}", supplier);
                setSupplierMethod.invoke(extAu, supplier);
            } catch (Exception e) {
                LOGGER.debug(
                        "Failed to set CheckForUpdates supplier - expected to fail at 2.11.0", e);
            }
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    private JSONObject getMandatoryRequestData() {
        JSONObject json = new JSONObject();
        json.put("zapVersion", Constant.PROGRAM_VERSION);
        json.put("os", getOS().toString());
        json.put(
                "osVersion",
                System.getProperty("os.name") + " : " + System.getProperty("os.version"));
        json.put("javaVersion", System.getProperty("java.version"));
        json.put("zapType", ZAP.getProcessType().name());
        json.put("container", isInContainer() ? containerName : "");
        return json;
    }

    private void addExtendedData(JSONObject data) {
        data.put("telIndex", ++telIndex);
        data.put("telUuid", this.getParam().getTelemetryUuid());
        data.put("mode", Control.getSingleton().getMode().name());
        data.put("locale", Constant.getLocale().toString());
        data.put("memory", Runtime.getRuntime().freeMemory());
        data.put("uptime", ManagementFactory.getRuntimeMXBean().getUptime());
    }

    private HttpMessage sendServiceRequest(String url, JSONObject data)
            throws IOException, InvalidServiceUrlException {
        LOGGER.debug("Sending request to ZAP service {}", url);
        HttpMessage msg = new HttpMessage(new URI(url, true));
        msg.getRequestHeader().setMethod(HttpRequestHeader.POST);
        msg.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.JSON_CONTENT_TYPE);
        msg.getRequestBody().setBody(data.toString());
        msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
        getHttpSender().sendAndReceive(msg, HTTP_REQUEST_CONFIG);
        if (msg.getResponseHeader().getStatusCode() != HttpStatusCode.OK) {
            throw new IOException(
                    "Expected '200 OK' but got '"
                            + msg.getResponseHeader().getStatusCode()
                            + " "
                            + msg.getResponseHeader().getReasonPhrase()
                            + "'");
        }
        if (!msg.getRequestHeader().isSecure()) {
            // Only access the ZAP services over https
            throw new InvalidServiceUrlException(msg.getRequestHeader().getURI().toString());
        }
        return msg;
    }

    private ZapXmlConfiguration getServiceData(String url)
            throws IOException, ConfigurationException, InvalidServiceUrlException {
        LOGGER.debug("Getting ZAP service data from {}", url);
        HttpMessage msg = sendServiceRequest(url, getMandatoryRequestData());
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        config.setDelimiterParsingDisabled(true);
        config.load(new StringReader(msg.getResponseBody().toString()));
        return config;
    }

    public ZapXmlConfiguration getCheckForUpdatesData()
            throws IOException, ConfigurationException, InvalidServiceUrlException {
        return getServiceData(ZAP_CFU_SERVICE);
    }

    public ZapXmlConfiguration getNewsData()
            throws IOException, ConfigurationException, InvalidServiceUrlException {
        return getServiceData(ZAP_NEWS_SERVICE);
    }

    private ZapXmlConfiguration get() {
        try {
            return getCheckForUpdatesData();
        } catch (Exception e) {
            if (e.getMessage().contains("PKIX path building failed")) {
                String message = Constant.messages.getString("callhome.pkix.fail.message");
                LOGGER.warn(message);
                updateOutput(message);
                return null;
            }
            LOGGER.error(e.getMessage(), e);
        }
        return null;
    }

    private InMemoryStats getInMemoryStats() {
        return Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionStats.class)
                .getInMemoryStats();
    }

    protected void addStatistics(JSONObject data, InMemoryStats inMemoryStats) {
        if (inMemoryStats != null) {
            inMemoryStats.getStats("").entrySet().stream()
                    .filter(new StatsPredicate<>())
                    .forEach(entry -> data.put(entry.getKey(), entry.getValue()));

            // Sum the filtered site stats
            Map<String, Long> siteStats = new HashMap<>();
            inMemoryStats.getAllSiteStats("").values().stream()
                    .forEach(
                            entry ->
                                    entry.entrySet().stream()
                                            .filter(new StatsPredicate<>())
                                            .forEach(
                                                    e2 ->
                                                            siteStats.merge(
                                                                    e2.getKey(),
                                                                    e2.getValue(),
                                                                    Long::sum)));

            // Add them all to the data
            siteStats.entrySet().forEach(entry -> data.put(entry.getKey(), entry.getValue()));
        }
    }

    private class StatsPredicate<E> implements Predicate<Entry<String, Long>> {
        @Override
        public boolean test(Entry<String, Long> t) {
            String key = t.getKey();
            return key.startsWith("openapi.")
                    || key.startsWith("soap.")
                    || key.startsWith("spiderAjax.")
                    || key.startsWith("stats.alertFilter")
                    || key.startsWith("stats.ascan.")
                    || key.startsWith("stats.auth.")
                    || key.startsWith("stats.auto.")
                    || key.startsWith("stats.break.")
                    || key.startsWith("stats.code.")
                    || key.startsWith("stats.exim.")
                    || key.startsWith("stats.fuzz.")
                    || key.startsWith("stats.graphql.")
                    || key.startsWith("stats.hud.")
                    || key.startsWith("stats.oast.")
                    || key.startsWith("stats.openapi.")
                    || key.startsWith("stats.quickstart.")
                    || key.startsWith("stats.reports.")
                    || key.startsWith("stats.script.")
                    || key.startsWith("stats.selenium.")
                    || key.startsWith("stats.spider.")
                    || key.startsWith("stats.websockets.")
                    || PSCAN_PATTERN.matcher(key).matches();
        }
    }

    private void uploadTelemetryStartData() {
        new Thread(
                        () -> {
                            JSONObject data = getMandatoryRequestData();
                            data.put("teltype", "add-ons");
                            addExtendedData(data);
                            // Add the add-on summary details
                            ExtensionFactory.getAddOnLoader().getAddOnCollection()
                                    .getInstalledAddOns().stream()
                                    .forEach(
                                            oe -> data.put(oe.getId(), oe.getVersion().toString()));

                            lastTelemetryData = data;

                            try {
                                this.sendServiceRequest(ZAP_TEL_SERVICE, data);
                            } catch (Exception e) {
                                LOGGER.error(e.getMessage(), e);
                            }
                        },
                        "ZAP-telemetry-start")
                .start();
    }

    private JSONObject getTelemetryData() {
        JSONObject data = getMandatoryRequestData();
        data.put("teltype", "stats");
        addExtendedData(data);
        addStatistics(data, getInMemoryStats());
        return data;
    }

    private void uploadTelemetrySessionData(JSONObject data) {
        lastTelemetryData = data;

        try {
            this.sendServiceRequest(ZAP_TEL_SERVICE, data);
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    protected JSONObject getLastTelemetryData() {
        return this.lastTelemetryData;
    }

    public static OS getOS() {
        if (os == null) {
            if (Constant.isWindows()) {
                os = OS.WINDOWS;
            } else if (Constant.isKali()) {
                os = OS.KALI;
            } else if (isBackBox()) {
                os = OS.BACK_BOX;
            } else if (Constant.isLinux()) {
                os = OS.LINUX;
            } else if (Constant.isMacOsX()) {
                os = OS.MAC_OS;
            } else {
                os = OS.UNKNOWN;
            }
        }
        return os;
    }

    // XXX: Use Constant.isBackBox() from 2.12.0
    private static boolean isBackBox() {
        if (onBackBox == null) {
            onBackBox = Boolean.FALSE;
            File issueFile = new File(ISSUE_FILE);
            if (Constant.isLinux() && !Constant.isDailyBuild() && issueFile.exists()) {
                // Ignore the fact we're on BackBox if this is a daily build - they will only have
                // been installed manually
                try {
                    String content = new String(Files.readAllBytes(issueFile.toPath()));
                    if (content.startsWith(BACK_BOX_ID)) {
                        onBackBox = Boolean.TRUE;
                    }
                } catch (Exception e) {
                    // Ignore
                }
            }
        }
        return onBackBox;
    }

    /** Copied from core Constant to fix a bug in the webswing & kali detection logic in 2.11.0 */
    // XXX Change back to using the core after 2.12.0
    public static boolean isInContainer() {
        if (inContainer == null) {
            // This is created by the Docker files from 2.11
            File containerFile = new File(ZAP_CONTAINER_FILE);
            File flatpakFile = new File(FLATPAK_FILE);
            File snapFile = new File(SNAP_FILE);
            if (Constant.isLinux() && containerFile.exists()) {
                inContainer = true;
                String home = System.getenv(HOME_ENVVAR);
                boolean inWebSwing = home != null && home.contains(WEBSWING_NAME);
                try {
                    containerName =
                            new String(
                                            Files.readAllBytes(containerFile.toPath()),
                                            StandardCharsets.UTF_8)
                                    .trim();
                    if (inWebSwing) {
                        // Append the webswing name so we don't loose the docker image name
                        containerName += "." + WEBSWING_NAME;
                    }
                } catch (IOException e) {
                    // Ignore
                }
            } else if (flatpakFile.exists()) {
                inContainer = true;
                containerName = FLATPAK_NAME;
            } else if (snapFile.exists()) {
                inContainer = true;
                containerName = SNAP_NAME;
            } else {
                inContainer = false;
            }
        }
        return inContainer;
    }

    private HttpSender getHttpSender() {
        if (httpSender == null) {
            httpSender =
                    new HttpSender(
                            Model.getSingleton().getOptionsParam().getConnectionParam(),
                            true,
                            HttpSender.CHECK_FOR_UPDATES_INITIATOR);
        }
        return httpSender;
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString(PREFIX + ".name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }

    public CallHomeParam getParam() {
        if (param == null) {
            param = new CallHomeParam();
        }
        return param;
    }

    @Override
    public void sessionAboutToChange(Session session) {
        if (Constant.isSilent() || !getParam().isTelemetryEnabled()) {
            LOGGER.info("Shh! Silent mode or telemetry turned off");
            return;
        }
        LocalDateTime now = LocalDateTime.now();
        if (this.lastSessionCreated == null) {
            // Can't upload start data here as the cmdline options will not have been checked
            lastSessionCreated = now;
        } else {
            Duration duration = Duration.between(this.lastSessionCreated, now);
            if (duration.getSeconds() > 2) {
                // When a session changes there are 2 of these events in quick succession, just
                // upload on the first one

                JSONObject data = this.getTelemetryData();

                new Thread(
                                () -> {
                                    this.uploadTelemetrySessionData(data);
                                    lastSessionCreated = now;
                                },
                                "ZAP-telemetry-stats")
                        .start();
            }
        }
    }

    @Override
    public void destroy() {
        if (Constant.isSilent() || !getParam().isTelemetryEnabled()) {
            return;
        }
        LocalDateTime now = LocalDateTime.now();
        if (this.lastSessionCreated != null) {
            Duration duration = Duration.between(this.lastSessionCreated, now);
            if (duration.getSeconds() <= 2) {
                return;
            }
        }
        this.uploadTelemetrySessionData(this.getTelemetryData());
        lastSessionCreated = now;
    }

    @Override
    public void sessionChanged(Session session) {
        // Nothing to do
    }

    @Override
    public void sessionScopeChanged(Session session) {
        // Nothing to do
    }

    @Override
    public void sessionModeChanged(Mode mode) {
        // Nothing to do
    }

    protected CommandLineArgument[] getCommandLineArguments() {
        arguments[ARG_NO_TEL_IDX] =
                new CommandLineArgument(
                        "-notel",
                        0,
                        null,
                        "",
                        "-notel                   "
                                + Constant.messages.getString(PREFIX + ".cmdline.notel.help"));
        return arguments;
    }

    @Override
    public void execute(CommandLineArgument[] args) {
        if (arguments[ARG_NO_TEL_IDX].isEnabled()) {
            this.getParam().setTelemetryEnabled(false);
        }
        if (Constant.isSilent() || !getParam().isTelemetryEnabled()) {
            LOGGER.info("Shh! Silent mode or telemetry turned off");
        } else {
            this.uploadTelemetryStartData();
        }
    }

    @Override
    public boolean handleFile(File file) {
        // Not supported
        return false;
    }

    @Override
    public List<String> getHandledExtensions() {
        // Not supported
        return null;
    }

    private static void updateOutput(String message) {
        if (View.isInitialised()) {
            StringBuilder sb = new StringBuilder(message.length() + 1);
            sb.append(message).append('\n');
            View.getSingleton().getOutputPanel().append(sb.toString());
        }
    }
}
