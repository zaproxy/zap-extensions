/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ExtensionContext.Namespace;
import org.junit.jupiter.api.extension.ExtensionContext.Store;
import org.parosproxy.paros.Constant;

/**
 * An extension that automatically initialises the ZAP install and home directories before each test
 * and cleans them up afterwards.
 */
public class ZapSetupExtension implements BeforeAllCallback, BeforeEachCallback {

    private static final Namespace NAMESPACE = Namespace.create(ZapSetupExtension.class);

    private static final String TEMP_DIR_KEY = "zapTempDir";
    private static final String INSTALL_DIR_KEY = "zapInstallDir";
    private static final String HOME_DIR_KEY = "zapHomeDir";

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        Path tempDir = Files.createTempDirectory("zap-test-");
        Path installDir = Files.createTempDirectory(tempDir, "install");
        Path xmlDir = Files.createDirectory(installDir.resolve("xml"));
        Files.createFile(xmlDir.resolve("log4j2.properties"));

        Store store = context.getStore(NAMESPACE);
        store.put(INSTALL_DIR_KEY, installDir);
        store.put(TEMP_DIR_KEY, (AutoCloseable) () -> deleteDir(tempDir));
    }

    @Override
    public void beforeEach(ExtensionContext context) throws Exception {
        Store classStore = context.getParent().orElseThrow().getStore(NAMESPACE);
        Path installDir = classStore.get(INSTALL_DIR_KEY, Path.class);

        Path homeDir = Files.createTempDirectory(installDir.getParent(), "home");
        context.getStore(NAMESPACE).put(HOME_DIR_KEY, (AutoCloseable) () -> deleteDir(homeDir));

        Constant.setZapInstall(installDir.toAbsolutePath().toString());
        Constant.setZapHome(homeDir.toAbsolutePath().toString());
    }

    private static void deleteDir(Path dir) throws IOException {
        if (dir == null || Files.notExists(dir)) {
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
}
