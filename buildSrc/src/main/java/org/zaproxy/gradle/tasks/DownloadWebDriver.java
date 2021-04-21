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
import java.io.File;
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
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.OutputFile;
import org.gradle.api.tasks.TaskAction;
import org.gradle.workers.WorkAction;
import org.gradle.workers.WorkParameters;
import org.gradle.workers.WorkQueue;
import org.gradle.workers.WorkerExecutor;

public abstract class DownloadWebDriver extends DefaultTask {

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

    @Input
    public abstract Property<Browser> getBrowser();

    @Input
    public abstract Property<String> getVersion();

    @Input
    public abstract Property<OS> getOs();

    @Input
    public abstract Property<Arch> getArch();

    @OutputFile
    public abstract RegularFileProperty getOutputFile();

    @Inject
    public abstract WorkerExecutor getWorkerExecutor();

    @TaskAction
    public void download() {
        WorkQueue workQueue = getWorkerExecutor().classLoaderIsolation();

        workQueue.submit(
                Download.class,
                params -> {
                    params.getBrowser().set(DriverManagerType.valueOf(toUpperCase(getBrowser())));
                    params.getWdVersion().set(getVersion().get());
                    params.getOs().set(OperatingSystem.valueOf(toUpperCase(getOs())));
                    params.getArch().set(Architecture.valueOf(toUpperCase(getArch())));
                    params.getOutputFile().set(getOutputFile());
                });
    }

    private static String toUpperCase(Property<? extends Enum<?>> property) {
        return property.get().name().toUpperCase(Locale.ROOT);
    }

    public interface DownloadWorkParameters extends WorkParameters {
        Property<DriverManagerType> getBrowser();

        Property<String> getWdVersion();

        Property<OperatingSystem> getOs();

        Property<Architecture> getArch();

        RegularFileProperty getOutputFile();
    }

    public abstract static class Download implements WorkAction<DownloadWorkParameters> {

        @Override
        public void execute() {
            WebDriverManager wdm = getInstance(getParameters().getBrowser().get());
            wdm.forceCache()
                    .avoidPreferences()
                    .avoidExport()
                    .avoidAutoVersion()
                    .version(getParameters().getWdVersion().get())
                    .operatingSystem(getParameters().getOs().get())
                    .architecture(getParameters().getArch().get())
                    .setup();

            File outputFile = getParameters().getOutputFile().get().getAsFile();
            try {
                Files.copy(
                        Paths.get(wdm.getBinaryPath()),
                        outputFile.toPath(),
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
