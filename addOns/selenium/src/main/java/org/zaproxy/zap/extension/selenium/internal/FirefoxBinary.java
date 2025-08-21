// Licensed to the Software Freedom Conservancy (SFC) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The SFC licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package org.zaproxy.zap.extension.selenium.internal;

import static java.util.stream.Collectors.toList;
import static org.openqa.selenium.Platform.MAC;
import static org.openqa.selenium.Platform.UNIX;
import static org.openqa.selenium.Platform.WINDOWS;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.openqa.selenium.Platform;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.os.ExecutableFinder;

/**
 * A wrapper around Firefox's binary. This allows us to locate the binary in a portable way.
 */
public class FirefoxBinary {

  private final String executable;

  public FirefoxBinary() {
    String systemBinary = locateFirefoxBinaryFromSystemProperty();
    if (systemBinary != null) {
      executable = systemBinary;
      return;
    }

    String platformBinary = locateFirefoxBinariesFromPlatform().findFirst().orElse(null);
    if (platformBinary != null) {
      executable = platformBinary;
      return;
    }

    throw new WebDriverException(
        "Cannot find firefox binary in PATH. "
            + "Make sure firefox is installed. OS appears to be: "
            + Platform.getCurrent());
  }

  public String getFile() {
    return executable;
  }

  /**
   * Locates the firefox binary from a system property. Will throw an exception if the binary cannot
   * be found.
   */
  static String locateFirefoxBinaryFromSystemProperty() {
    String binaryName = System.getProperty(FirefoxDriver.SystemProperty.BROWSER_BINARY);
    if (binaryName == null) return null;

    File binary = new File(binaryName);
    if (binary.exists() && !binary.isDirectory()) return binary.getAbsolutePath();

    Platform current = Platform.getCurrent();
    if (current.is(WINDOWS)) {
      if (!binaryName.endsWith(".exe")) {
        binaryName += ".exe";
      }

    } else if (current.is(MAC)) {
      if (!binaryName.endsWith(".app")) {
        binaryName += ".app";
      }
      binaryName += "/Contents/MacOS/firefox";
    }

    binary = new File(binaryName);
    if (binary.exists()) return binary.getAbsolutePath();

    throw new WebDriverException(
        String.format(
            "'%s' property set, but unable to locate the requested binary: %s",
            FirefoxDriver.SystemProperty.BROWSER_BINARY, binaryName));
  }

  /** Locates the firefox binary by platform. */
  private static Stream<String> locateFirefoxBinariesFromPlatform() {
    List<String> executables = new ArrayList<>();

    Platform current = Platform.getCurrent();
    if (current.is(WINDOWS)) {
      executables.addAll(
          Stream.of(
                  "Mozilla Firefox\\firefox.exe",
                  "Firefox Developer Edition\\firefox.exe",
                  "Nightly\\firefox.exe")
              .map(FirefoxBinary::getPathsInProgramFiles)
              .flatMap(List::stream)
              .map(File::new)
              .filter(File::exists)
              .map(File::getAbsolutePath)
              .collect(toList()));

    } else if (current.is(MAC)) {
      // system
      File binary = new File("/Applications/Firefox.app/Contents/MacOS/firefox");
      if (binary.exists()) {
        executables.add(binary.getAbsolutePath());
      }

      // user home
      binary = new File(System.getProperty("user.home") + binary.getAbsolutePath());
      if (binary.exists()) {
        executables.add(binary.getAbsolutePath());
      }

    } else if (current.is(UNIX)) {
      String systemFirefoxBin = new ExecutableFinder().find("firefox");
      if (systemFirefoxBin != null) {
        executables.add(new File(systemFirefoxBin).getAbsolutePath());
      }
    }

    String systemFirefox = new ExecutableFinder().find("firefox");
    if (systemFirefox != null) {
      Path firefoxPath = new File(systemFirefox).toPath();
      if (Files.isSymbolicLink(firefoxPath)) {
        try {
          Path realPath = firefoxPath.toRealPath();
          File file = realPath.getParent().resolve("firefox").toFile();
          if (file.exists()) {
            executables.add(file.getAbsolutePath());
          }
        } catch (IOException e) {
          // ignore this path
        }

      } else {
        executables.add(new File(systemFirefox).getAbsolutePath());
      }
    }

    return executables.stream();
  }

  private static List<String> getPathsInProgramFiles(final String childPath) {
    return Stream.of(getProgramFilesPath(), getProgramFiles86Path())
        .map(parent -> new File(parent, childPath).getAbsolutePath())
        .collect(Collectors.toList());
  }

  /**
   * Returns the path to the Windows Program Files. On non-English versions, this is not necessarily
   * "C:\Program Files".
   *
   * @return the path to the Windows Program Files
   */
  private static String getProgramFilesPath() {
    return getEnvVarPath("ProgramFiles", "C:\\Program Files").replace(" (x86)", "");
  }

  private static String getProgramFiles86Path() {
    return getEnvVarPath("ProgramFiles(x86)", "C:\\Program Files (x86)");
  }

  private static String getEnvVarPath(final String envVar, final String defaultValue) {
    return getEnvVarIgnoreCase(envVar)
        .map(File::new)
        .filter(File::exists)
        .map(File::getAbsolutePath)
        .orElseGet(() -> new File(defaultValue).getAbsolutePath());
  }

  private static Optional<String> getEnvVarIgnoreCase(String var) {
    return System.getenv().entrySet().stream()
        .filter(e -> e.getKey().equalsIgnoreCase(var))
        .findFirst()
        .map(Map.Entry::getValue);
  }
}
