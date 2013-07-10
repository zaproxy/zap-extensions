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
package org.zaproxy.zap.extension.svndigger;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.util.Arrays;
import java.util.Comparator;

/**
 * Simple utility class for listing the files to include in the ZapAddOn.xml file
 * @author simon
 *
 */
public class SvnDiggerFiles {
	
	public static final String ORIG = "src/org/zaproxy/zap/extension/svndigger/orig/"; 
	public static final String DEST = "src/org/zaproxy/zap/extension/svndigger/files/"; 

	public static void flattenFiles(File src, File target) {
		if (! src.exists()) {
			System.out.println("Does not exist: " + src.getAbsolutePath());
			return;
		}
		if (! src.isDirectory()) {
			System.out.println("Not a diretory: " + src.getAbsolutePath());
			return;
		}
		File[] files = src.listFiles();
		for (File f : files) {
			if (f.isDirectory()) {
				flattenFiles(f, target);
			} else if ( ! f.getName().startsWith(".")) {
				String fullname = f.getAbsolutePath();
				int relNameOffset = fullname.indexOf(ORIG) + ORIG.length();
				String flattennedName = "svndigger-" + fullname.substring(relNameOffset).replace("/", "-");
				File dest = new File(DEST, flattennedName);
				try {
					System.out.println("Copying " + f.getAbsolutePath() + " to " + dest.getAbsolutePath());
					copyFile(f, dest);
				} catch (IOException e) {
					System.out.println("Failed to copy " + f.getAbsolutePath() + " to " + dest.getAbsolutePath() + " " + e);
				}
			}
		}
	}

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
				System.out.print("\t\t<file>dirbuster/");
				String fullname = f.getAbsolutePath();
				int relNameOffset = fullname.indexOf(DEST) + DEST.length();
				System.out.print(fullname.substring(relNameOffset));
				System.out.println("</file>");
			}
		}
	}
	
	public static void copyFile(File sourceFile, File destFile) throws IOException {
	    if(!destFile.exists()) {
	        destFile.createNewFile();
	    }

	    FileChannel source = null;
	    FileChannel destination = null;

	    try {
	        source = new FileInputStream(sourceFile).getChannel();
	        destination = new FileOutputStream(destFile).getChannel();
	        destination.transferFrom(source, 0, source.size());
	    }
	    finally {
	        if(source != null) {
	            source.close();
	        }
	        if(destination != null) {
	            destination.close();
	        }
	    }
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// Note that the Licence.txt and ReadMe.txt are currently moved into a sub directory by hand 
		//flattenFiles(new File(ORIG), new File(DEST));
		listDir(new File(DEST));
	}


}
class FileNameComparitor implements Comparator<File> {

	@Override
	public int compare(File o1, File o2) {
		return o1.getName().compareTo(o2.getName());
	}
}
