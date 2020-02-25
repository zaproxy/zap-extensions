/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.gradle.tasks;

import io.github.bonigarcia.wdm.Architecture;
import io.github.bonigarcia.wdm.DriverManagerType;
import io.github.bonigarcia.wdm.FirefoxDriverManager;
import io.github.bonigarcia.wdm.OperatingSystem;
import io.github.bonigarcia.wdm.WebDriverManager;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.Optional;
import javax.inject.Inject;
import org.gradle.api.DefaultTask;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.model.ObjectFactory;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.OutputFile;
import org.gradle.api.tasks.TaskAction;
import org.gradle.workers.IsolationMode;
import org.gradle.workers.WorkerExecutor;

public class DownloadWebDriver extends DefaultTask {

    public enum Browser {
        CHROME,
        FIREFOX
    }

    public enum OS {
        LINUX,
        MAC,
        WIN
    }

    public enum Arch {
        X32,
        X64
    }

    private final WorkerExecutor workerExecutor;
    private final Property<Browser> browser;
    private final Property<String> version;
    private final Property<OS> os;
    private final Property<Arch> arch;
    private final RegularFileProperty outputFile;

    @Inject
    public DownloadWebDriver(WorkerExecutor workerExecutor) {
        this.workerExecutor = workerExecutor;
        ObjectFactory objects = getProject().getObjects();
        this.browser = objects.property(Browser.class);
        this.version = objects.property(String.class);
        this.os = objects.property(OS.class);
        this.arch = objects.property(Arch.class);
        this.outputFile = objects.fileProperty();
    }

    @Input
    public Property<Browser> getBrowser() {
        return browser;
    }

    @Input
    public Property<String> getVersion() {
        return version;
    }

    @Input
    public Property<OS> getOs() {
        return os;
    }

    @Input
    public Property<Arch> getArch() {
        return arch;
    }

    @OutputFile
    public RegularFileProperty getOutputFile() {
        return outputFile;
    }

    @TaskAction
    public void download() {
        workerExecutor.submit(
                Download.class,
                config -> {
                    config.setIsolationMode(IsolationMode.CLASSLOADER);
                    config.params(
                            DriverManagerType.valueOf(toUpperCase(browser)),
                            version.get(),
                            OperatingSystem.valueOf(toUpperCase(os)),
                            Architecture.valueOf(toUpperCase(arch)),
                            outputFile.get().getAsFile().getAbsolutePath());
                });
    }

    private static String toUpperCase(Property<? extends Enum<?>> property) {
        return property.get().name().toUpperCase(Locale.ROOT);
    }

    public static class Download implements Runnable {

        private final DriverManagerType browser;
        private final String wdVersion;
        private final OperatingSystem os;
        private final Architecture arch;
        private final String outputFile;

        @Inject
        public Download(
                DriverManagerType browser,
                String wdVersion,
                OperatingSystem os,
                Architecture arch,
                String outputFile) {
            this.browser = browser;
            this.wdVersion = wdVersion;
            this.os = os;
            this.arch = arch;
            this.outputFile = outputFile;
        }

        @Override
        public void run() {
            WebDriverManager wdm = getInstance(browser);
            wdm.forceCache()
                    .avoidPreferences()
                    .avoidExport()
                    .avoidAutoVersion()
                    .version(wdVersion)
                    .operatingSystem(os)
                    .architecture(arch)
                    .setup();

            try {
                Files.copy(
                        Paths.get(wdm.getBinaryPath()),
                        Paths.get(outputFile),
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException e) {
                throw new UncheckedIOException(
                        "Failed to copy the WebDriver from "
                                + wdm.getBinaryPath()
                                + " to "
                                + outputFile,
                        e);
            }
        }

        private static WebDriverManager getInstance(DriverManagerType browser) {
            switch (browser) {
                case CHROME:
                    return WebDriverManager.chromedriver();
                case FIREFOX:
                    return new FirefoxDriverManagerCustom();
                default:
                    throw new UnsupportedOperationException(
                            "Only Chrome and Firefox are currently supported.");
            }
        }

        private static class FirefoxDriverManagerCustom extends FirefoxDriverManager {

            FirefoxDriverManagerCustom() {
                instanceMap.put(DriverManagerType.FIREFOX, this);
            }

            @Override
            protected Optional<String> getDriverFromCache(
                    String driverVersion, Architecture arch, String os) {
                Optional<String> driver = super.getDriverFromCache(driverVersion, arch, os);
                if (isRequestedArch(driver, os, arch)) {
                    return driver;
                }
                return Optional.empty();
            }

            private static boolean isRequestedArch(
                    Optional<String> driver, String os, Architecture arch) {
                // macOS has only one geckodriver binary.
                if ("MAC".equals(os)) {
                    return true;
                }

                return driver.isPresent()
                        && driver.get()
                                .toLowerCase()
                                .contains(os.toLowerCase() + arch.toString().toLowerCase());
            }
        }
    }
}
