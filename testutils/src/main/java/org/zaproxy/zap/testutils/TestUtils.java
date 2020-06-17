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

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.ResourceBundle;
import net.htmlparser.jericho.Config;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.utils.I18N;

/**
 * Class with utility/helper methods for general tests.
 *
 * <p>Among other helper methods it allows to {@link #setUpZap() set up ZAP} and provides a {@link
 * #nano HTTP test server}.
 */
@ExtendWith(MockitoExtension.class)
public abstract class TestUtils {

    public static final String DEFAULT_CONTENT_TYPE = "text/html;charset=ISO-8859-1";

    /**
     * A temporary directory where ZAP home/installation dirs are created.
     *
     * <p>Can be used for other temporary files/dirs.
     */
    @TempDir protected static Path tempDir;

    static {
        Config.LoggerProvider = ZAP.JERICHO_LOGGER_PROVIDER;
    }

    private static String zapInstallDir;
    private static String zapHomeDir;

    /**
     * The resource bundle of the extension under test.
     *
     * <p>Lazily initialised, in {@link #mockMessages(Extension)}.
     */
    private static ResourceBundle extensionResourceBundle;

    /**
     * A HTTP test server.
     *
     * <p>The server is {@code null} if not started.
     *
     * @see #startServer()
     */
    protected HTTPDTestServer nano;

    @BeforeAll
    public static void beforeClass() throws Exception {
        Path installDir = Files.createDirectory(tempDir.resolve("install"));
        Path xmlDir = Files.createDirectory(installDir.resolve("xml"));
        Files.createFile(xmlDir.resolve("log4j.properties"));

        zapInstallDir = installDir.toAbsolutePath().toString();
        zapHomeDir = Files.createDirectory(tempDir.resolve("home")).toAbsolutePath().toString();
    }

    /** Sets up the log to ease debugging. */
    protected void setUpLog() {
        // Useful if you need to get some info when debugging
        BasicConfigurator.configure();
        ConsoleAppender ca = new ConsoleAppender();
        ca.setWriter(new OutputStreamWriter(System.out));
        ca.setLayout(new PatternLayout("%-5p [%t]: %m%n"));
        Logger.getRootLogger().addAppender(ca);
        Logger.getRootLogger().setLevel(Level.DEBUG);
    }

    /**
     * Sets up ZAP, by initialising the home/installation dirs and core classes (for example, {@link
     * Constant}, {@link Control}, {@link Model}).
     *
     * @throws Exception if an error occurred while setting up the dirs or core classes.
     * @see #setUpMessages()
     */
    protected void setUpZap() throws Exception {
        Constant.setZapInstall(zapInstallDir);
        Constant.setZapHome(zapHomeDir);

        Control control = mock(Control.class, withSettings().lenient());
        when(control.getExtensionLoader()).thenReturn(mock(ExtensionLoader.class));

        // Init all the things
        Constant.getInstance();
        setUpMessages();
        Control.initSingletonForTesting();
        Model.getSingleton();
    }

    /**
     * Starts the HTTP test server with a random port.
     *
     * <p>The port can be obtained with the method {@link HTTPDTestServer#getListeningPort()} from
     * the {@link #nano test server}.
     *
     * @throws IOException if an error occurred while starting the server.
     * @see #stopServer()
     */
    protected void startServer() throws IOException {
        startServer(getRandomPort());
    }

    /**
     * Starts the HTTP test server with the specified port.
     *
     * <p>It's recommended to use {@link #startServer()} instead, using a fixed port might lead to
     * random failures when the port is already in use.
     *
     * @param port the port to listen to.
     * @throws IOException if an error occurred while starting the server.
     * @see #stopServer()
     */
    protected void startServer(int port) throws IOException {
        stopServer();

        nano = new HTTPDTestServer(port);
        nano.start();
    }

    private static int getRandomPort() throws IOException {
        try (ServerSocket server = new ServerSocket(0)) {
            return server.getLocalPort();
        }
    }

    /**
     * Stops the HTTP test server.
     *
     * @see #startServer()
     */
    protected void stopServer() {
        if (nano == null) {
            return;
        }
        nano.stop();
    }

    /**
     * Called when {@link #setUpZap() setting up ZAP} to initialise the {@link Constant#messages
     * messages}.
     *
     * @see #mockMessages(Extension)
     */
    protected void setUpMessages() {}

    /**
     * Deletes the ZAP's home directory.
     *
     * @throws Exception if an error occurred while deleting the home directory.
     */
    @AfterEach
    public void shutDown() throws Exception {
        deleteDir(Paths.get(zapHomeDir));
    }

    private static void deleteDir(Path dir) throws IOException {
        if (Files.notExists(dir)) {
            return;
        }

        Files.walkFileTree(
                dir,
                new SimpleFileVisitor<Path>() {

                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
                            throws IOException {
                        Files.delete(file);
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult postVisitDirectory(Path dir, IOException e)
                            throws IOException {
                        if (e != null) {
                            throw e;
                        }
                        Files.delete(dir);
                        return FileVisitResult.CONTINUE;
                    }
                });
    }

    /**
     * Creates a (GET) HTTP message with the given path, for the {@link #nano test server}.
     *
     * <p>The response contains empty HTML tags, {@code <html></html>}.
     *
     * @param path the path component of the request-target, for example, {@code /dir/file.txt}.
     * @return the HTTP message, never {@code null}.
     * @throws IllegalStateException if the server was not {@link #startServer() started} prior
     *     calling this method.
     * @throws HttpMalformedHeaderException if an error occurred while creating the HTTP message.
     */
    protected HttpMessage getHttpMessage(String path) throws HttpMalformedHeaderException {
        return this.getHttpMessage("GET", DEFAULT_CONTENT_TYPE, path, "<html></html>");
    }

    /**
     * Creates a (GET) HTTP message with the given path, for the {@link #nano test server}.
     *
     * <p>The response contains empty HTML tags, {@code <html></html>}.
     *
     * @param path the path component of the request-target, for example, {@code /dir/file.txt}.
     * @return the HTTP message, never {@code null}.
     * @throws IllegalStateException if the server was not {@link #startServer() started} prior
     *     calling this method.
     * @throws HttpMalformedHeaderException if an error occurred while creating the HTTP message.
     */
    protected HttpMessage getHttpMessage(String path, String contentType)
            throws HttpMalformedHeaderException {
        return this.getHttpMessage("GET", contentType, path, "<html></html>");
    }

    /**
     * Creates a HTTP message with the given data, for the {@link #nano test server}.
     *
     * @param method the HTTP method.
     * @param path the path component of the request-target, for example, {@code /dir/file.txt}.
     * @param responseBody the body of the response.
     * @return the HTTP message, never {@code null}.
     * @throws IllegalStateException if the server was not {@link #startServer() started} prior
     *     calling this method.
     * @throws HttpMalformedHeaderException if an error occurred while creating the HTTP message.
     */
    protected HttpMessage getHttpMessage(String method, String path, String responseBody)
            throws HttpMalformedHeaderException {
        return getHttpMessage(method, DEFAULT_CONTENT_TYPE, path, responseBody);
    }
    /**
     * Creates a HTTP message with the given data, for the {@link #nano test server}.
     *
     * @param method the HTTP method.
     * @param contentType the Content-Type header
     * @param path the path component of the request-target, for example, {@code /dir/file.txt}.
     * @param responseBody the body of the response.
     * @return the HTTP message, never {@code null}.
     * @throws IllegalStateException if the server was not {@link #startServer() started} prior
     *     calling this method.
     * @throws HttpMalformedHeaderException if an error occurred while creating the HTTP message.
     */
    protected HttpMessage getHttpMessage(
            String method, String contentType, String path, String responseBody)
            throws HttpMalformedHeaderException {
        if (nano == null) {
            throw new IllegalStateException("The HTTP test server was not started.");
        }

        HttpMessage msg = new HttpMessage();
        StringBuilder reqHeaderSB = new StringBuilder();
        reqHeaderSB.append(method);
        reqHeaderSB.append(" http://localhost:");
        reqHeaderSB.append(nano.getListeningPort());
        reqHeaderSB.append(path);
        reqHeaderSB.append(" HTTP/1.1\r\n");
        reqHeaderSB.append("Host: localhost:").append(nano.getListeningPort()).append("\r\n");
        reqHeaderSB.append("User-Agent: ZAP\r\n");
        reqHeaderSB.append("Pragma: no-cache\r\n");
        msg.setRequestHeader(reqHeaderSB.toString());

        msg.setResponseBody(responseBody);

        StringBuilder respHeaderSB = new StringBuilder();
        respHeaderSB.append("HTTP/1.1 200 OK\r\n");
        respHeaderSB.append("Server: Apache-Coyote/1.1\r\n");
        respHeaderSB.append("Content-Type: ");
        respHeaderSB.append(contentType);
        respHeaderSB.append("\r\n");
        respHeaderSB.append("Content-Length: ");
        respHeaderSB.append(msg.getResponseBody().length());
        respHeaderSB.append("\r\n");
        msg.setResponseHeader(respHeaderSB.toString());

        return msg;
    }

    /**
     * Gets the contents of the file with the given path.
     *
     * @param resourcePath the path to the resource.
     * @return the contents of the file.
     * @see #getResourcePath(String)
     */
    public String getHtml(String resourcePath) {
        return this.getHtml(resourcePath, (Map<String, String>) null);
    }

    /**
     * Gets the contents of the file with the given path, replaced with the given parameters.
     *
     * @param resourcePath the path to the resource.
     * @param params the parameters to replace in the contents, might be {@code null}.
     * @return the contents of the file.
     * @see #getResourcePath(String)
     */
    public String getHtml(String resourcePath, String[][] params) {
        Map<String, String> map = new HashMap<>();
        for (int i = 0; i < params.length; i++) {
            map.put(params[i][0], params[i][1]);
        }
        return this.getHtml(resourcePath, map);
    }

    /**
     * Gets the contents of the file with the given path, replaced with the given parameters.
     *
     * @param resourcePath the path to the resource.
     * @param params the parameters to replace in the contents, might be {@code null}.
     * @return the contents of the file.
     * @see #getResourcePath(String)
     */
    public String getHtml(String resourcePath, Map<String, String> params) {
        Path file = getResourcePath(resourcePath);
        try {
            String html = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
            if (params != null) {
                // Replace all of the supplied parameters
                for (Entry<String, String> entry : params.entrySet()) {
                    html = html.replaceAll("@@@" + entry.getKey() + "@@@", entry.getValue());
                }
            }
            return html;
        } catch (IOException e) {
            System.err.println("Failed to read file " + file.toAbsolutePath());
            throw new RuntimeException(e);
        }
    }

    /**
     * Gets the (file system) path to the given resource.
     *
     * <p>The resource path is obtained with the caller class using {@link
     * Class#getResource(String)}.
     *
     * @param resourcePath the path to the resource.
     * @return the path, never {@code null}.
     */
    protected Path getResourcePath(String resourcePath) {
        try {
            return Paths.get(getClass().getResource(resourcePath).toURI());
        } catch (URISyntaxException e) {
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

    /**
     * Mocks the class variable {@link Constant#messages} using the resource bundle
     * (Messages.properties) created from the given extension.
     *
     * <p>The extension's messages are asserted that exists before obtaining it.
     *
     * <p>Resource messages that do not belong to the extension (that is, do not start with {@link
     * Extension#getI18nPrefix()}) have an empty {@code String}.
     *
     * @param extension the target extension to mock the messages
     */
    protected static void mockMessages(final Extension extension) {
        mockMessages(
                extension.getClass().getPackage().getName()
                        + ".resources."
                        + Constant.MESSAGES_PREFIX,
                extension.getI18nPrefix());
    }

    /**
     * Mocks the class variable {@link Constant#messages} using the resource bundle with the given
     * base name and prefix.
     *
     * <p>The messages with the given prefix are asserted that exist before obtaining them.
     *
     * <p>Resource messages that do not have the {@code prefix} have an empty {@code String}.
     *
     * @param baseName the base name of the resource bundle.
     * @param prefix the prefix for the resource bundle.
     */
    protected static void mockMessages(String baseName, String prefix) {
        I18N i18n = mock(I18N.class, withSettings().lenient());
        Constant.messages = i18n;

        given(i18n.getLocal()).willReturn(Locale.getDefault());

        extensionResourceBundle = getExtensionResourceBundle(baseName);
        when(i18n.getString(anyString()))
                .thenAnswer(
                        new Answer<String>() {

                            @Override
                            public String answer(InvocationOnMock invocation) {
                                String key = (String) invocation.getArguments()[0];
                                if (key.startsWith(prefix)) {
                                    assertKeyExists(key);
                                    return extensionResourceBundle.getString(key);
                                }
                                // Return an empty string for non extension's messages.
                                return "";
                            }
                        });

        when(i18n.getString(anyString(), any()))
                .thenAnswer(
                        new Answer<String>() {

                            @Override
                            public String answer(InvocationOnMock invocation) {
                                Object[] args = invocation.getArguments();
                                String key = (String) args[0];
                                if (key.startsWith(prefix)) {
                                    assertKeyExists(key);
                                    return MessageFormat.format(
                                            extensionResourceBundle.getString(key),
                                            Arrays.copyOfRange(args, 1, args.length));
                                }
                                // Return an empty string for non extension's messages.
                                return "";
                            }
                        });
    }

    private static ResourceBundle getExtensionResourceBundle(String baseName) {
        return ResourceBundle.getBundle(
                baseName,
                Locale.ROOT,
                TestUtils.class.getClassLoader(),
                ResourceBundle.Control.getControl(ResourceBundle.Control.FORMAT_PROPERTIES));
    }

    private static void assertKeyExists(String key) {
        assertTrue(
                extensionResourceBundle != null,
                "The extension's ResourceBundle was not intialiased.");
        assertTrue(extensionResourceBundle.containsKey(key), "No resource message for: " + key);
    }

    /**
     * Creates a matcher that matches when the examined {@code Alert} has a name that matches with
     * one loaded with the given key.
     *
     * @param key the key for the name
     * @return the name matcher
     */
    protected static Matcher<Alert> hasNameLoadedWithKey(final String key) {
        assertKeyExists(key);
        return new BaseMatcher<Alert>() {

            @Override
            public boolean matches(Object actualValue) {
                return ((Alert) actualValue).getName().equals(Constant.messages.getString(key));
            }

            @Override
            public void describeTo(Description description) {
                description.appendText("alert name ").appendValue(Constant.messages.getString(key));
            }

            @Override
            public void describeMismatch(Object item, Description description) {
                description.appendText("was ").appendValue(((Alert) item).getName());
            }
        };
    }

    /**
     * Creates a matcher that matches when the examined {@code Alert} has a name that contains the
     * string loaded with the given key.
     *
     * @param key the key for the name
     * @return the name matcher
     */
    protected static Matcher<Alert> containsNameLoadedWithKey(final String key) {
        assertKeyExists(key);
        return new BaseMatcher<Alert>() {

            @Override
            public boolean matches(Object actualValue) {
                return ((Alert) actualValue).getName().contains(Constant.messages.getString(key));
            }

            @Override
            public void describeTo(Description description) {
                description
                        .appendText("alert name contains ")
                        .appendValue(Constant.messages.getString(key));
            }

            @Override
            public void describeMismatch(Object item, Description description) {
                description.appendText("was ").appendValue(((Alert) item).getName());
            }
        };
    }

    /**
     * Creates a matcher that matches when the examined {@code Alert} has a other info that contains
     * the string loaded with the given key.
     *
     * @param key the key for the name
     * @return the name matcher
     * @param params the parameters to format the message.
     */
    protected static Matcher<Alert> containsOtherInfoLoadedWithKey(
            final String key, final Object... params) {
        assertKeyExists(key);
        return new BaseMatcher<Alert>() {

            @Override
            public boolean matches(Object actualValue) {
                return ((Alert) actualValue)
                        .getOtherInfo()
                        .contains(Constant.messages.getString(key, params));
            }

            @Override
            public void describeTo(Description description) {
                description
                        .appendText("alert other info contains ")
                        .appendValue(Constant.messages.getString(key, params));
            }

            @Override
            public void describeMismatch(Object item, Description description) {
                description.appendText("was ").appendValue(((Alert) item).getOtherInfo());
            }
        };
    }
}
