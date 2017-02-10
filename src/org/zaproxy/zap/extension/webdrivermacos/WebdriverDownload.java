/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
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
package org.zaproxy.zap.extension.webdrivermacos;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Paths;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;

public class WebdriverDownload {

	/**
	 * The webdriver files are not held in the repo to prevent space problems.
	 * Run the program to download the files before building the add-on. It will
	 * need to be changed whenever there are new versions.
	 * 
	 * @param args
	 */
	public static void main(String[] args) {

		// Geckodriver releases: https://github.com/mozilla/geckodriver/releases

		downloadDriver(
				"https://github.com/mozilla/geckodriver/releases/download/v0.14.0/geckodriver-v0.14.0-macos.tar.gz",
				"files/webdriver/macos/64/", "geckodriver");

		// Chromedriver releases:
		// https://sites.google.com/a/chromium.org/chromedriver/downloads

		downloadDriver("https://chromedriver.storage.googleapis.com/2.27/chromedriver_mac64.zip",
				"files/webdriver/macos/64/", "chromedriver");
	}

    private static void downloadDriver(String urlStr, String destDir, String destFile) {
        String baseDir = "src/";
        if (Paths.get("").toAbsolutePath().toString().endsWith("build")) {
            // Likely to be being invoked from the build script
            baseDir = "../src/";
        }
		File dest = new File(
				baseDir + WebdriverDownload.class.getPackage().getName().replace(".", "/") + "/" + destDir + destFile);
        if (dest.exists()) {
            System.out.println("Already exists: " + dest.getAbsolutePath());
            return;
        }
		File parent = dest.getParentFile();
		if (!parent.exists() && !parent.mkdirs()) {
			System.out.println("Failed to create directory : " + dest.getParentFile().getAbsolutePath());
		}
		byte[] buffer = new byte[1024];
		if (urlStr.endsWith(".zip")) {
			try {
				URL url = new URL(urlStr);
				ZipInputStream zipIn = new ZipInputStream(url.openStream());
				ZipEntry entry;

				boolean isFound = false;
				while ((entry = zipIn.getNextEntry()) != null) {
					if (destFile.equals(entry.getName())) {
						isFound = true;
						FileOutputStream out = new FileOutputStream(dest);
						int read = 0;
						while ((read = zipIn.read(buffer)) != -1) {
							out.write(buffer, 0, read);
						}
						out.close();
						System.out.println("Updated: " + dest.getAbsolutePath());

					} else {
						System.out.println("Found " + entry.getName());
					}
					zipIn.closeEntry();
					entry = zipIn.getNextEntry();
				}

				zipIn.close();

				if (!isFound) {
					System.out.println("Failed to find " + destFile);
					System.exit(1);
				}

			} catch (IOException ex) {
				ex.printStackTrace();
				System.exit(1);
			}
		} else if (urlStr.endsWith(".tar.gz")) {
			try {
				URL url = new URL(urlStr);
				GZIPInputStream gzis = new GZIPInputStream(url.openStream());

				File tarFile = new File(dest.getAbsolutePath() + ".tar");
				FileOutputStream out = new FileOutputStream(tarFile);

				int len;
				while ((len = gzis.read(buffer)) > 0) {
					out.write(buffer, 0, len);
				}

				gzis.close();
				out.close();

				TarArchiveInputStream tar = new TarArchiveInputStream(new FileInputStream(tarFile));
				ArchiveEntry entry;
				boolean isFound = false;
				while ((entry = tar.getNextEntry()) != null) {
					if (destFile.equals(entry.getName())) {
						out = new FileOutputStream(dest);
						isFound = true;

						int read = 0;
						while ((read = tar.read(buffer)) != -1) {
							out.write(buffer, 0, read);
						}
						out.close();
						System.out.println("Updated: " + dest.getAbsolutePath());
					}
				}
				tar.close();
				tarFile.delete();
				if (!isFound) {
					System.out.println("Failed to find " + destFile);
					System.exit(1);
				}

			} catch (IOException ex) {
				ex.printStackTrace();
				System.exit(1);
			}
		}
	}
}
