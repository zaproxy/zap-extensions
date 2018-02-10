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
package org.zaproxy.zap.extension.fuzzdb;

import java.io.File;
import java.util.Arrays;
import java.util.Comparator;

/**
 * Simple utility class for listing the files to include in the ZapAddOn.xml file
 * @author simon
 *
 */
public class FuzzdbFiles {
	
	public static final String ROOT = "src/org/zaproxy/zap/extension/fuzzdb/files/fuzzers/fuzzdb"; 
	
	public static void listDir(File dir) {
		if (! dir.exists()) {
			System.out.println("Does not exist: " + dir.getAbsolutePath());
			return;
		}
		if (! dir.isDirectory()) {
			System.out.println("Not a diretory: " + dir.getAbsolutePath());
			return;
		}
		File[] files = dir.listFiles();
		Arrays.sort(files, new FileNameComparitor());
		for (File f : files) {
			if (f.isDirectory()) {
				listDir(f);
			} else if ( ! f.getName().startsWith(".")) {
				System.out.print("\t\t<file>fuzzers/fuzzdb");
				String fullname = f.getAbsolutePath();
				int relNameOffset = fullname.indexOf(ROOT) + ROOT.length();
				System.out.print(fullname.substring(relNameOffset));
				System.out.println("</file>");
			}
		}
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		listDir(new File(ROOT));
	}


}
class FileNameComparitor implements Comparator<File> {

	@Override
	public int compare(File o1, File o2) {
		return o1.getName().compareTo(o2.getName());
	}
}
