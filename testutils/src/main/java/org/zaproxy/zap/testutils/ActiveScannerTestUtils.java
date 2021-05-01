/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.testutils;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.PluginFactory;
import org.parosproxy.paros.core.scanner.Scanner;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.parosproxy.paros.network.ConnectionParam;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/**
 * Class with utility/helper methods for active scanner tests ({@link
 * org.parosproxy.paros.core.scanner.Plugin Plugin}.
 *
 * <p>It automatically starts the HTTP test server for each test.
 *
 * @param <T> the type of the active scanner.
 */
public abstract class ActiveScannerTestUtils<T extends AbstractPlugin> extends TestUtils {

    /**
     * The recommended maximum number of messages that a scanner can send in {@link
     * org.parosproxy.paros.core.scanner.Plugin.AttackStrength#LOW AttackStrength.LOW}, per
     * parameter being scanned.
     */
    protected static final int NUMBER_MSGS_ATTACK_STRENGTH_LOW = 6;

    /**
     * The recommended maximum number of messages that a scanner can send in {@link
     * org.parosproxy.paros.core.scanner.Plugin.AttackStrength#MEDIUM AttackStrength.MEDIUM}, per
     * parameter being scanned.
     */
    protected static final int NUMBER_MSGS_ATTACK_STRENGTH_MEDIUM = 12;

    /**
     * The recommended maximum number of messages that a scanner can send in {@link
     * org.parosproxy.paros.core.scanner.Plugin.AttackStrength#HIGH AttackStrength.HIGH}, per
     * parameter being scanned.
     */
    protected static final int NUMBER_MSGS_ATTACK_STRENGTH_HIGH = 24;

    /**
     * The maximum number of messages that a scanner can send in {@link
     * org.parosproxy.paros.core.scanner.Plugin.AttackStrength#INSANE AttackStrength.INSANE}, per
     * parameter being scanned.
     */
    // Arbitrary value, there's no recommended number.
    protected static final int NUMBER_MSGS_ATTACK_STRENGTH_INSANE = 75;

    /**
     * The recommended maximum number of messages that a scanner can send per page being scanned at
     * {@link org.parosproxy.paros.core.scanner.Plugin.AttackStrength#LOW AttackStrength.LOW}.
     *
     * @see <a
     *     href="https://github.com/zaproxy/zap-extensions/wiki/AddOnsBeta">https://github.com/zaproxy/zap-extensions/wiki/AddOnsBeta</a>
     */
    protected static final int NUMBER_MSGS_ATTACK_PER_PAGE_LOW = 36; // 6x6

    protected static final int NUMBER_MSGS_ATTACK_PER_PAGE_MED = 72; // 6x12
    protected static final int NUMBER_MSGS_ATTACK_PER_PAGE_HIGH = 144; // 6x24
    protected static final int NUMBER_MSGS_ATTACK_PER_PAGE_INSANE = 500; // whatever

    protected T rule;
    protected HostProcess parent;
    protected ScannerParam scannerParam;

    /** The alerts raised during the scan. */
    protected List<Alert> alertsRaised;

    /** The HTTP messages sent during the scan. */
    protected List<HttpMessage> httpMessagesSent;

    /** The count of messages (HTTP and others) sent during the scan. */
    protected int countMessagesSent;

    public ActiveScannerTestUtils() {
        super();
    }

    @BeforeEach
    public void setUp() throws Exception {
        setUpZap();

        PluginFactory pluginFactory = mock(PluginFactory.class);
        ScanPolicy scanPolicy = mock(ScanPolicy.class);
        when(scanPolicy.getPluginFactory()).thenReturn(pluginFactory);

        ConnectionParam connectionParam = new ConnectionParam();

        scannerParam = new ScannerParam();
        scannerParam.load(new ZapXmlConfiguration());
        RuleConfigParam ruleConfigParam = new RuleConfigParam();
        Scanner parentScanner =
                new Scanner(scannerParam, connectionParam, scanPolicy, ruleConfigParam);

        startServer();
        int port = nano.getListeningPort();

        alertsRaised = new ArrayList<>();
        httpMessagesSent = new ArrayList<>();
        parent =
                spy(
                        new HostProcess(
                                "localhost:" + port,
                                parentScanner,
                                scannerParam,
                                connectionParam,
                                scanPolicy,
                                ruleConfigParam) {
                            @Override
                            public void alertFound(Alert arg1) {
                                alertsRaised.add(arg1);
                            }

                            @Override
                            public void notifyNewMessage(HttpMessage msg) {
                                httpMessagesSent.add(msg);
                                countMessagesSent++;
                            }

                            @Override
                            public void notifyNewMessage(Plugin plugin) {
                                countMessagesSent++;
                            }

                            @Override
                            public void notifyNewMessage(Plugin plugin, HttpMessage msg) {
                                httpMessagesSent.add(msg);
                                countMessagesSent++;
                            }
                        });

        rule = createScanner();
        if (rule.getConfig() == null) {
            rule.setConfig(new ZapXmlConfiguration());
        }
    }

    @AfterEach
    public void shutDownServer() throws Exception {
        stopServer();
    }

    protected abstract T createScanner();

    @TestFactory
    Collection<DynamicTest> commonScanRuleTests() {
        List<DynamicTest> commonTests = new ArrayList<>();
        commonTests.add(testScanRuleHasName());
        addTestsSendReasonableNumberOfMessages(commonTests);
        return commonTests;
    }

    private DynamicTest testScanRuleHasName() {
        return dynamicTest(
                "shouldHaveI18nNonEmptyName",
                () -> {
                    setUp();
                    try {
                        shouldHaveI18nNonEmptyName();
                    } finally {
                        shutDownServer();
                    }
                });
    }

    private void shouldHaveI18nNonEmptyName() {
        // Given / When
        String name = rule.getName();
        // Then
        assertThat(name, not(isEmptyOrNullString()));
        assertThat(
                "Name does not seem to be i18n'ed, not found in the resource bundle:" + name,
                extensionResourceBundle.keySet().stream()
                        .map(extensionResourceBundle::getString)
                        .anyMatch(str -> str.equals(name)));
    }

    private void addTestsSendReasonableNumberOfMessages(List<DynamicTest> tests) {
        T scanRule = createScanner();

        String messagePath = "";
        Function<Plugin.AttackStrength, Integer> maxNumberMessagesProvider = null;
        if (scanRule instanceof AbstractAppParamPlugin) {
            messagePath = "?p=v";
            maxNumberMessagesProvider = this::getRecommendMaxNumberMessagesPerParam;
        } else if (scanRule instanceof AbstractAppPlugin) {
            maxNumberMessagesProvider = this::getRecommendMaxNumberMessagesPerPage;
        }

        if (maxNumberMessagesProvider != null) {
            for (Plugin.AttackStrength strength :
                    EnumSet.range(Plugin.AttackStrength.LOW, Plugin.AttackStrength.INSANE)) {
                String strengthName =
                        StringUtils.capitalize(strength.name().toLowerCase(Locale.ROOT));
                String testName =
                        String.format(
                                "shouldSendReasonableNumberOfMessagesIn%sStrength", strengthName);
                int maxNumberMessages = maxNumberMessagesProvider.apply(strength);
                String path = messagePath;
                tests.add(
                        dynamicTest(
                                testName,
                                () -> {
                                    setUp();
                                    try {
                                        shouldSendReasonableNumberOfMessages(
                                                strength, maxNumberMessages, path);
                                    } finally {
                                        shutDownServer();
                                    }
                                }));
            }
        }
    }

    /**
     * Tests the number of messages sent for a given strength.
     *
     * <p>The tests for all strengths are created dynamically using this and other referenced
     * methods.
     *
     * <p>The recommended maximum number of messages is obtained from {@link
     * #getRecommendMaxNumberMessagesPerParam(org.parosproxy.paros.core.scanner.Plugin.AttackStrength)}
     * and {@link
     * #getRecommendMaxNumberMessagesPerPage(org.parosproxy.paros.core.scanner.Plugin.AttackStrength)}
     * depending on the type of the scan rule being tested.
     *
     * <p>Should not be overridden in normal cases.
     *
     * @param strength the strength to test.
     * @param maxNumberMessages the maximum number of messages allowed to be sent.
     * @param defaultPath the default path used to create the {@link
     *     #getHttpMessageForSendReasonableNumberOfMessages(String) test message}.
     * @throws HttpMalformedHeaderException if an exception occurred while creating the test HTTP
     *     message.
     * @see #setupServerForSendReasonableNumberOfMessages()
     * @see #isIgnoreAlertsRaisedInSendReasonableNumberOfMessages()
     */
    protected void shouldSendReasonableNumberOfMessages(
            Plugin.AttackStrength strength, int maxNumberMessages, String defaultPath)
            throws HttpMalformedHeaderException {
        // Given
        setupServerForSendReasonableNumberOfMessages();
        rule.setAttackStrength(strength);
        rule.init(getHttpMessageForSendReasonableNumberOfMessages(defaultPath), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(lessThanOrEqualTo(maxNumberMessages)));
        if (!isIgnoreAlertsRaisedInSendReasonableNumberOfMessages()) {
            assertThat(alertsRaised, hasSize(0));
        }
    }

    /**
     * Setups the {@link TestUtils#nano test server} for the tests that verify the number of
     * messages sent for a given strength.
     *
     * <p>Does nothing by default. Scan rules test class should override this method to setup the
     * test server in a way that maximises the number of the messages sent by the scan rule.
     *
     * @see
     *     #shouldSendReasonableNumberOfMessages(org.parosproxy.paros.core.scanner.Plugin.AttackStrength,
     *     int, String)
     */
    protected void setupServerForSendReasonableNumberOfMessages() {}

    /**
     * Gets the recommended maximum number of messages that a scanner can send per parameter for the
     * given strength.
     *
     * @param strength the attack strength.
     * @return the recommended maximum number of messages.
     * @see AbstractAppParamPlugin
     */
    protected int getRecommendMaxNumberMessagesPerParam(Plugin.AttackStrength strength) {
        switch (strength) {
            case LOW:
                return NUMBER_MSGS_ATTACK_STRENGTH_LOW;
            case MEDIUM:
            default:
                return NUMBER_MSGS_ATTACK_STRENGTH_MEDIUM;
            case HIGH:
                return NUMBER_MSGS_ATTACK_STRENGTH_HIGH;
            case INSANE:
                return NUMBER_MSGS_ATTACK_STRENGTH_INSANE;
        }
    }

    /**
     * Gets the recommended maximum number of messages that a scanner can send per page for the
     * given strength.
     *
     * @param strength the attack strength.
     * @return the recommended maximum number of messages.
     * @see AbstractAppPlugin
     */
    protected int getRecommendMaxNumberMessagesPerPage(Plugin.AttackStrength strength) {
        switch (strength) {
            case LOW:
                return NUMBER_MSGS_ATTACK_PER_PAGE_LOW;
            case MEDIUM:
            default:
                return NUMBER_MSGS_ATTACK_PER_PAGE_MED;
            case HIGH:
                return NUMBER_MSGS_ATTACK_PER_PAGE_HIGH;
            case INSANE:
                return NUMBER_MSGS_ATTACK_PER_PAGE_INSANE;
        }
    }

    /**
     * Gets the HTTP message that causes the scan rule to send the most messages, to verify that it
     * does not exceed (too much) the recommended limits.
     *
     * <p>The default message is created with {@link #getHttpMessage(String)} using the given
     * default path, a query parameter for {@link AbstractAppParamPlugin} and an empty path for
     * {@link AbstractAppPlugin}.
     *
     * @param defaultPath the default path
     * @return the HTTP message.
     */
    protected HttpMessage getHttpMessageForSendReasonableNumberOfMessages(String defaultPath)
            throws HttpMalformedHeaderException {
        return getHttpMessage(defaultPath);
    }

    /**
     * Tells whether or not the scan rule raises alerts even when testing the number of messages
     * sent.
     *
     * <p>In normal cases no alert should be raised, as that usually reduces the number of messages
     * sent.
     *
     * <p>Default value: {@code false}.
     *
     * @return {@code true} if the scan rule raises alerts, {@code false} otherwise.
     */
    protected boolean isIgnoreAlertsRaisedInSendReasonableNumberOfMessages() {
        return false;
    }
}
