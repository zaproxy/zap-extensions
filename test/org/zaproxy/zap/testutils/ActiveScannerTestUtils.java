/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP development team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.testutils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.mockito.Mockito;
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
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/**
 * Class with utility/helper methods for active scanner tests ({@link org.parosproxy.paros.core.scanner.Plugin Plugin}.
 * <p>
 * It automatically starts the HTTP test server for each test.
 * 
 * @param <T> the type of the active scanner.
 */
public abstract class ActiveScannerTestUtils<T extends AbstractPlugin> extends TestUtils {

    /**
     * The recommended maximum number of messages that a scanner can send in
     * {@link org.parosproxy.paros.core.scanner.Plugin.AttackStrength#LOW AttackStrength.LOW}, per parameter being scanned.
     */
    protected static final int NUMBER_MSGS_ATTACK_STRENGTH_LOW = 6;

    /**
     * The recommended maximum number of messages that a scanner can send in
     * {@link org.parosproxy.paros.core.scanner.Plugin.AttackStrength#MEDIUM AttackStrength.MEDIUM}, per parameter being
     * scanned.
     */
    protected static final int NUMBER_MSGS_ATTACK_STRENGTH_MEDIUM = 12;

    /**
     * The recommended maximum number of messages that a scanner can send in
     * {@link org.parosproxy.paros.core.scanner.Plugin.AttackStrength#HIGH AttackStrength.HIGH}, per parameter being scanned.
     */
    protected static final int NUMBER_MSGS_ATTACK_STRENGTH_HIGH = 24;

    /**
     * The maximum number of messages that a scanner can send in
     * {@link org.parosproxy.paros.core.scanner.Plugin.AttackStrength#INSANE AttackStrength.INSANE}, per parameter being
     * scanned.
     */
    // Arbitrary value, there's no recommended number.
    protected static final int NUMBER_MSGS_ATTACK_STRENGTH_INSANE = 75;

    /**
     * The recommended maximum number of messages that a scanner can send per page being
     * scanned at {@link org.parosproxy.paros.core.scanner.Plugin.AttackStrength#LOW AttackStrength.LOW}.
     * @see <a href="https://github.com/zaproxy/zap-extensions/wiki/AddOnsBeta">https://github.com/zaproxy/zap-extensions/wiki/AddOnsBeta</a>
     */
    protected static final int NUMBER_MSGS_ATTACK_PER_PAGE_LOW = 36;// 6x6
    protected static final int NUMBER_MSGS_ATTACK_PER_PAGE_MED = 72;// 6x12
    protected static final int NUMBER_MSGS_ATTACK_PER_PAGE_HIGH = 144;// 6x24
    protected static final int NUMBER_MSGS_ATTACK_PER_PAGE_INSANE = 500; //whatever

    protected T rule;
    protected HostProcess parent;
    protected ScannerParam scannerParam;

    /**
     * The alerts raised during the scan.
     */
    protected List<Alert> alertsRaised;

    /**
     * The HTTP messages sent during the scan.
     */
    protected List<HttpMessage> httpMessagesSent;

    /**
     * The count of messages (HTTP and others) sent during the scan.
     */
    protected int countMessagesSent;

    public ActiveScannerTestUtils() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        setUpZap();

        PluginFactory pluginFactory = Mockito.mock(PluginFactory.class);
        ScanPolicy scanPolicy = Mockito.mock(ScanPolicy.class);
        Mockito.when(scanPolicy.getPluginFactory()).thenReturn(pluginFactory);
        
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
        parent = new HostProcess(
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
                super.notifyNewMessage(msg);
                httpMessagesSent.add(msg);
                countMessagesSent++;
            }

            @Override
            public void notifyNewMessage(Plugin plugin) {
                super.notifyNewMessage(plugin);
                countMessagesSent++;
            }

            @Override
            public void notifyNewMessage(Plugin plugin, HttpMessage msg) {
                super.notifyNewMessage(plugin, msg);
                httpMessagesSent.add(msg);
                countMessagesSent++;
            }
        };
        
        rule = createScanner();
        if (rule.getConfig() == null) {
            rule.setConfig(new ZapXmlConfiguration());
        }
    }

    @After
    public void shutDownServer() throws Exception {
        stopServer();
    }

    protected abstract T createScanner();

    @Override
    public String getHtml(String name, Map<String, String> params) {
        return super.getHtml(getClass().getSimpleName() + "/" + name, params);
    }

    /**
     * Gets the recommended maximum number of messages that a scanner can send per parameter for the given strength.
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
     * Gets the recommended maximum number of messages that a scanner can send per page for the given strength.
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

}