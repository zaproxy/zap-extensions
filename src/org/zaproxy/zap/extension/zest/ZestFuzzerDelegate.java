/**
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * 
 * @author Alessandro Secco: seccoale@gmail.com
 */
package org.zaproxy.zap.extension.zest;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.owasp.jbrofuzz.core.Fuzzer;
import org.owasp.jbrofuzz.core.NoSuchFuzzerException;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.ExtensionFuzz;
import org.zaproxy.zap.extension.fuzz.FileFuzzer;

public class ZestFuzzerDelegate {
	private ExtensionFuzz extensionFuzz=(ExtensionFuzz)org.parosproxy.paros.control.Control.getSingleton().
	        getExtensionLoader().getExtension(ExtensionFuzz.NAME);
	private File fuzzerDir = null;
	private File fuzzerCustomDir = null;
	private File fuzzerJBroFuzzDir = null;
	public final static String JBROFUZZ_CATEGORY_PREFIX=ExtensionFuzz.JBROFUZZ_CATEGORY_PREFIX;

	private static final Logger logger = Logger.getLogger(ZestFuzzerDelegate.class);

	public ZestFuzzerDelegate() {
	}

	private File getFuzzerDir() {
		if (this.fuzzerDir == null) {
			// TODO this will need to use the new method for getting the install dir
			fuzzerDir = new File(Constant.getInstance().FUZZER_DIR);
		}
		return fuzzerDir;
	}

	private File getCustomFuzzerDir() {
		if (fuzzerCustomDir == null) {
			// TODO this will need to use the new method for getting the install dir
			fuzzerCustomDir = new File(Constant.getInstance().FUZZER_CUSTOM_DIR);
		}
		return fuzzerCustomDir;
	}
	
	private File getJBroFuzzFuzzerDir() {
		if (fuzzerJBroFuzzDir == null) {
			fuzzerJBroFuzzDir = new File(getCustomFuzzerDir(), "jbrofuzz");
			if (! fuzzerJBroFuzzDir.exists()) {
				fuzzerJBroFuzzDir.mkdirs();
			}
		}
		return fuzzerJBroFuzzDir;
	}
	
	private File fromFuzzer(Fuzzer fuzzer) throws IOException{
		// Copy the fuzzer to filestore, otherwise Zest wont be able to access it
		String fuzzerFileName = fuzzer.getName();
		File copyOfFuzzer = new File(getJBroFuzzFuzzerDir(), fuzzerFileName);
		FileWriter writer = new FileWriter(copyOfFuzzer);
		while(fuzzer.hasNext()){
			writer.write(fuzzer.next()+"\n");
		}
		writer.close();
		return copyOfFuzzer;
	}

	public List<String> getFuzzersForCategory(String category){
		if (category == null || category.length() == 0) {
			List<String> list = new ArrayList<String>();
			list.add("");
			return list;
		} else if (category.startsWith(JBROFUZZ_CATEGORY_PREFIX)) {
			return extensionFuzz.getJBroFuzzFuzzerNames(category);
		} else if (category.equals(Constant.messages.getString("fuzz.category.custom"))) {
			return extensionFuzz.getCustomFileList();
		} else {
			return extensionFuzz.getFileFuzzerNames(category);
		}
	}

	private FileFuzzer getFileFuzzer(String category, String name){
		return extensionFuzz.getFileFuzzer(category, name);
	}
	
	private FileFuzzer getCustomFileFuzzer(String name){
		return extensionFuzz.getCustomFileFuzzer(name);
	}
	
	private Fuzzer getJBroFuzzer(String name) throws NoSuchFuzzerException{
		return extensionFuzz.getJBroFuzzer(name);
	}
	
	public List<String> getAllFuzzCategories(){
		List<String> cats = new ArrayList<String>();
		cats.add("");
		for (String cat : extensionFuzz.getJBroFuzzCategories()) {
			if (cat.length() > 0) {
				cats.add(cat);
			}
		}
		for (String cat : extensionFuzz.getFileFuzzerCategories()) {
			if (cat.length() > 0) {
				cats.add(cat);
			}
		}
		cats.add(Constant.messages.getString("fuzz.category.custom"));
		return cats;
	}
	
	public File getFuzzerFile (String category, String fuzzerName) {
		File fuzzerFile = null;
		if (fuzzerName == null || fuzzerName.length() == 0) {
			return null;
		} else if (category.startsWith(JBROFUZZ_CATEGORY_PREFIX)) {
			Fuzzer fuzzer;
			try {
				fuzzer = getJBroFuzzer(fuzzerName);
				fuzzerFile = fromFuzzer(fuzzer);
			} catch (NoSuchFuzzerException e) {
				logger.error(e.getMessage(), e);
			} catch (IOException e) {
				logger.error(e.getMessage(), e);
			}
			
		} else if (category.equals(Constant.messages.getString("fuzz.category.custom"))) {
			String absolutePath = getCustomFileFuzzer(fuzzerName).getFileName();
			absolutePath = getCustomFuzzerDir().getAbsolutePath() +
					File.separator + absolutePath;
			fuzzerFile = new File(absolutePath);

		} else {
			String absolutePath = getCustomFuzzerDir().getAbsolutePath() + 
					File.separator + category.replace(" / ", File.separator) +
					File.separator + getFileFuzzer(category, fuzzerName).getFileName();
			fuzzerFile = new File(absolutePath);
		}
		return fuzzerFile;

	}
	
	public class ZestFuzzerFileDelegate{
		private File file;
		String category=null;
		public ZestFuzzerFileDelegate(String absolutePath){
			this.file=new File(absolutePath);
		}
		public ZestFuzzerFileDelegate(File file) {
			this.file=file;
		}
		public File getFile(){
			return this.file;
		}
		public File toFuzzerFolder(){
			File fuzzFile=new File(getFuzzerDir().getAbsolutePath()+File.separator+file.getName());
			return fuzzFile;
		}
		public File toFuzzerFolder(String category){
			File fuzzFile=new File(getFuzzerDir().getAbsolutePath()+File.separator+category+File.separator+file.getName());
			return fuzzFile;
		}
		@Override
		public String toString(){
			String toReturn=file.getParentFile().getName()+File.separator+file.getName();
			return toReturn;
		}
		public String getCategory(){
			return this.category;
		}
		public void setCategory(String category){
			String pathToCat=getFuzzerDir().getAbsolutePath()+File.separator+category;
			File catDir=new File(pathToCat);
			if(!catDir.exists()){
				catDir.mkdir();
			}
			this.file=new File(pathToCat+File.separator+file.getName());
			this.category=catDir.getName();
		}
	}
}
