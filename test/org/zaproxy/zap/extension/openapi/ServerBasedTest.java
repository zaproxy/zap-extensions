/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP development team
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
package org.zaproxy.zap.extension.openapi;

import java.io.File;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
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
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ScannerTestUtils;
import org.zaproxy.zap.utils.ClassLoaderUtil;

public abstract class ServerBasedTest extends ScannerTestUtils {

    private static final String INSTALL_PATH = "test/resources/install";
    private static final File HOME_DIR = new File("test/resources/home");
    private static final String BASE_RESOURCE_DIR = "test/resources/org/zaproxy/zap/extension/openapi/";

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
    public static void beforeClass() {
    }

    public ServerBasedTest() {
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
        Constant.setZapInstall(INSTALL_PATH);
        HOME_DIR.mkdirs();
        Constant.setZapHome(HOME_DIR.getAbsolutePath());

        File langDir = new File(Constant.getZapInstall(), "lang");
        ClassLoaderUtil.addFile(langDir.getAbsolutePath());
        // Init all the things
        Constant.getInstance();
        mockMessages(new ExtensionOpenApi());
        Control.initSingletonForTesting();
        Model.getSingleton();

        int port = 9090;
        nano = new HTTPDTestServer(port);
        nano.start();
        
        alertsRaised = new ArrayList<>();
        httpMessagesSent = new ArrayList<>();
    }
    
    @After
    public void shutDown() throws Exception {
        nano.stop();
        File dir = new File("test/resources/home");
        FileUtils.deleteDirectory(dir);
    }
    
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
    
    public static String getHtml(String name) {
        return getHtml(name, (Map<String, String>)null);
    }

    public static String getHtml(String name, String[][] params) {
        Map<String, String> map = new HashMap<String, String>();
        for (int i=0; i < params.length; i++) {
            map.put(params[i][0], params[i][1]);
        }
        return getHtml(name, map);
    }

    public static String getHtml(String name, Map<String, String> params) {
        String fileName = BASE_RESOURCE_DIR + "/" + name;
        try {
            String html = FileUtils.readFileToString(new File(fileName));
            if (params != null) {
                // Replace all of the supplied parameters
                for (Entry<String, String> entry : params.entrySet()) {
                    html = html.replaceAll("@@@" + entry.getKey() + "@@@", entry.getValue());
                }
            }
            return html;
        } catch (IOException e) {
            System.err.println("Failed to read file " + new File(fileName).getAbsolutePath());
            throw new RuntimeException(e);
        }
    }
}