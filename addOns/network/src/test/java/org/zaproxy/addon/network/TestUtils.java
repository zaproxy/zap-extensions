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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.io.IOException;
import java.net.ServerSocket;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.Locale;
import java.util.ResourceBundle;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.utils.I18N;

public abstract class TestUtils {

    @TempDir protected static Path tempDir;

    private static String zapInstallDir;
    private static String zapHomeDir;

    protected static ResourceBundle extensionResourceBundle;

    @BeforeAll
    public static void beforeClass() throws Exception {
        Path installDir = Files.createDirectory(tempDir.resolve("install"));
        Path xmlDir = Files.createDirectory(installDir.resolve("xml"));
        Files.createFile(xmlDir.resolve("log4j2.properties"));

        zapInstallDir = installDir.toAbsolutePath().toString();
        createHomeDirectory();
    }

    private static void createHomeDirectory() throws Exception {
        zapHomeDir = Files.createTempDirectory(tempDir, "home").toAbsolutePath().toString();
    }

    protected void setUpZap() throws Exception {
        Constant.setZapInstall(zapInstallDir);
        createHomeDirectory();
        Constant.setZapHome(zapHomeDir);

        Control control = mock(Control.class, withSettings().strictness(Strictness.LENIENT));
        when(control.getExtensionLoader()).thenReturn(mock(ExtensionLoader.class));

        // Init all the things
        Constant.getInstance();
        Control.initSingletonForTesting();
        Model.getSingleton();
    }

    protected static int getRandomPort() throws IOException {
        try (ServerSocket server = new ServerSocket(0)) {
            return server.getLocalPort();
        }
    }

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

    protected static void mockMessages(final Extension extension) {
        String baseName =
                extension.getClass().getPackage().getName()
                        + ".resources."
                        + Constant.MESSAGES_PREFIX;
        String prefix = extension.getI18nPrefix();
        I18N i18n = mock(I18N.class, withSettings().strictness(Strictness.LENIENT));
        Constant.messages = i18n;

        given(i18n.getLocal()).willReturn(Locale.getDefault());

        extensionResourceBundle = getExtensionResourceBundle(baseName);
        when(i18n.getString(anyString()))
                .thenAnswer(
                        invocation -> {
                            String key = (String) invocation.getArguments()[0];
                            if (key.startsWith(prefix)) {
                                assertKeyExists(key);
                                return extensionResourceBundle.getString(key);
                            }
                            // Return an empty string for non extension's messages.
                            return "";
                        });

        when(i18n.getString(anyString(), any(Object[].class)))
                .thenAnswer(
                        invocation -> {
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
                        });

        when(i18n.containsKey(anyString()))
                .thenAnswer(
                        invocation -> {
                            String key = (String) invocation.getArguments()[0];
                            if (key.startsWith(prefix)) {
                                return extensionResourceBundle.containsKey(key);
                            }
                            // Return true for non extension's messages.
                            return true;
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
        assertNotNull(
                extensionResourceBundle, "The extension's ResourceBundle was not intialiased.");
        assertTrue(extensionResourceBundle.containsKey(key), "No resource message for: " + key);
    }
}
