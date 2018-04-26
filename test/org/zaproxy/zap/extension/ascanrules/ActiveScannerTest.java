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
package org.zaproxy.zap.extension.ascanrules;

import java.io.File;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.rules.TemporaryFolder;
import org.mockito.Mockito;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.PluginFactory;
import org.parosproxy.paros.core.scanner.Scanner;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.ConnectionParam;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ScannerTestUtils;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.utils.ClassLoaderUtil;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public abstract class ActiveScannerTest<T extends AbstractPlugin> extends ScannerTestUtils {

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

    private static final String BASE_RESOURCE_DIR = "/org/zaproxy/zap/extension/ascanrules/";

    @ClassRule
    public static TemporaryFolder zapDir = new TemporaryFolder();
    private static String zapInstallDir;
    private static String zapHomeDir;

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

    protected HTTPDTestServer nano;

    @BeforeClass
    public static void beforeClass() throws Exception {
        File installDir = zapDir.newFolder("install");
        Path langDir = Files.createDirectory(installDir.toPath().resolve("lang"));
        Files.createFile(langDir.resolve("Messages.properties"));
        Path xmlDir = Files.createDirectory(installDir.toPath().resolve("xml"));
        Files.createFile(xmlDir.resolve("log4j.properties"));
        Path configXmlPath = Files.createFile(xmlDir.resolve("config.xml"));
        Files.write(configXmlPath, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><config></config>".getBytes(StandardCharsets.UTF_8));

        zapInstallDir = installDir.getAbsolutePath();
        zapHomeDir = zapDir.newFolder("home").getAbsolutePath();
    }

    public ActiveScannerTest() {
        super();
    }

    /**
     * Sets up the log to ease debugging.
     */
    protected void setUpLog() {
        // Useful if you need to get some info when debugging
        BasicConfigurator.configure();
        ConsoleAppender ca = new ConsoleAppender();
        ca.setWriter(new OutputStreamWriter(System.out));
        ca.setLayout(new PatternLayout("%-5p [%t]: %m%n"));
        Logger.getRootLogger().addAppender(ca);
        Logger.getRootLogger().setLevel(Level.DEBUG);
    }

    @Before
    public void setUp() throws Exception {
        Constant.setZapInstall(zapInstallDir);
        Constant.setZapHome(zapHomeDir);

        File langDir = new File(Constant.getZapInstall(), "lang");
        ClassLoaderUtil.addFile(langDir.getAbsolutePath());
        
        ExtensionLoader extLoader = Mockito.mock(ExtensionLoader.class);
        Control control = Mockito.mock(Control.class);
        Mockito.when (control.getExtensionLoader()).thenReturn(extLoader);

        // Init all the things
        Constant.getInstance();
        mockMessages(new ExtensionAscanRules());
        Control.initSingletonForTesting();
        Model.getSingleton();

        PluginFactory pluginFactory = Mockito.mock(PluginFactory.class);
        ScanPolicy scanPolicy = Mockito.mock(ScanPolicy.class);
        Mockito.when(scanPolicy.getPluginFactory()).thenReturn(pluginFactory);
        
        ConnectionParam connectionParam = new ConnectionParam();
        
        scannerParam = new ScannerParam();
        scannerParam.load(new ZapXmlConfiguration());
        RuleConfigParam ruleConfigParam = new RuleConfigParam();
        Scanner parentScanner =
                new Scanner(scannerParam, connectionParam, scanPolicy, ruleConfigParam);

        int port = 9090;
        nano = new HTTPDTestServer(port);
        nano.start();
        
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
    }
    
    @After
    public void shutDown() throws Exception {
        nano.stop();
        FileUtils.deleteDirectory(new File(zapHomeDir));
    }

    protected abstract T createScanner();
    
    protected HttpMessage getHttpMessage(String url) throws HttpMalformedHeaderException {
        return this.getHttpMessage("GET", url, "<html></html>");
        
    }
    protected HttpMessage getHttpMessage(String method, String url, String body) throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage();
        StringBuilder reqHeaderSB = new StringBuilder();
        reqHeaderSB.append(method);
        reqHeaderSB.append(" http://localhost:");
        reqHeaderSB.append(this.nano.getListeningPort()); 
        reqHeaderSB.append(url);
        reqHeaderSB.append(" HTTP/1.1\r\n");
        reqHeaderSB.append("Host: www.any_domain_name.org\r\n");
        reqHeaderSB.append("User-Agent: ZAP\r\n");
        reqHeaderSB.append("Pragma: no-cache\r\n");
        msg.setRequestHeader(reqHeaderSB.toString());

        msg.setResponseBody(body);
        
        StringBuilder respHeaderSB = new StringBuilder();
        respHeaderSB.append("HTTP/1.1 200 OK\r\n");
        respHeaderSB.append("Server: Apache-Coyote/1.1\r\n");
        respHeaderSB.append("Content-Type: text/html;charset=ISO-8859-1\r\n");
        respHeaderSB.append("Content-Length: ");
        respHeaderSB.append(msg.getResponseBody().length());
        respHeaderSB.append("\r\n");
        msg.setResponseHeader(respHeaderSB.toString());

        return msg;
    }
    
    public String getHtml(String name) {
        return this.getHtml(name, (Map<String, String>)null);
    }

    public String getHtml(String name, String[][] params) {
        Map<String, String> map = new HashMap<String, String>();
        for (int i=0; i < params.length; i++) {
            map.put(params[i][0], params[i][1]);
        }
        return this.getHtml(name, map);
    }

    public String getHtml(String name, Map<String, String> params) {
        File file = new File(getClass().getResource(BASE_RESOURCE_DIR + this.getClass().getSimpleName() + "/" + name).getPath());
        try {
            String html = FileUtils.readFileToString(file, StandardCharsets.UTF_8);
            if (params != null) {
                // Replace all of the supplied parameters
                for (Entry<String, String> entry : params.entrySet()) {
                    html = html.replaceAll("@@@" + entry.getKey() + "@@@", entry.getValue());
                }
            }
            return html;
        } catch (IOException e) {
            System.err.println("Failed to read file " + file.getAbsolutePath());
            throw new RuntimeException(e);
        }
    }

    /**
     * Returns a {@code TechSet} with the given technologies.
     *
     * @param techs the technologies to be included in the {@code TechSet}.
     * @return a {@code TechSet} with the given technologies.
     */
    protected TechSet techSet(Tech... techs) {
        TechSet techSet = new TechSet();
        if (techs == null || techs.length == 0) {
            return techSet;
        }

        for (Tech tech : techs) {
            techSet.include(tech);
        }
        return techSet;
    }

    /**
     * Returns a {@code TechSet} with all technologies except the given ones.
     *
     * @param techs the technologies to be excluded from the {@code TechSet}.
     * @return a {@code TechSet} without the given technologies.
     */
    protected TechSet techSetWithout(Tech... techs) {
        TechSet techSet = new TechSet(TechSet.AllTech);
        if (techs == null || techs.length == 0) {
            return techSet;
        }

        for (Tech tech : techs) {
            techSet.exclude(tech);
        }
        return techSet;
    }

    /**
     * Returns the technologies of the given base type(s) (for example, {@link Tech#Db}).
     *
     * @param techs the base technology types to be included.
     * @return the technologies of the given base type(s).
     */
    protected Tech[] techsOf(Tech... techs) {
        if (techs == null || techs.length == 0) {
            return new Tech[0];
        }

        List<Tech> techsWithParent = new ArrayList<>();
        List<Tech> techList = Arrays.asList(techs);
        for (Tech tech : Tech.builtInTech) {
            Tech parentTech = tech.getParent();
            if (parentTech != null && techList.contains(parentTech)) {
                techsWithParent.add(tech);
            }
        }
        techsWithParent.addAll(techList);
        return techsWithParent.toArray(new Tech[techList.size()]);
    }

}