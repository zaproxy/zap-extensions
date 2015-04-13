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
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.owasp.jbrofuzz.core.Database;
import org.owasp.jbrofuzz.core.Fuzzer;
import org.owasp.jbrofuzz.core.NoSuchFuzzerException;
import org.parosproxy.paros.Constant;

public class ZestFuzzerDelegate {
	private File fuzzerDir = null;
	private File fuzzerJBroFuzzDir = null;

	public static final String JBROFUZZ_CATEGORY_PREFIX = "jbrofuzz / ";

	private static final Logger logger = Logger.getLogger(ZestFuzzerDelegate.class);

	public ZestFuzzerDelegate() {
		this.loadFiles();
	}

	private File getFuzzerDir() {
		if (this.fuzzerDir == null) {
			fuzzerDir = new File(Constant.getInstance().FUZZER_DIR);
		}
		return fuzzerDir;
	}

	private File getJBroFuzzFuzzerDir() {
		if (fuzzerJBroFuzzDir == null) {
			fuzzerJBroFuzzDir = new File(getFuzzerDir(), "jbrofuzz");
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
			return getJBroFuzzFuzzerNames(category);
		} else {
			return getFileFuzzerNames(category);
		}
	}

	private FileFuzzer getFileFuzzer(String category, String name){
		return getFileFuzzer(category, name);
	}
	
	public List<String> getAllFuzzCategories(){
		List<String> cats = new ArrayList<String>();
		cats.add("");
		for (String cat : getJBroFuzzCategories()) {
			if (cat.length() > 0) {
				cats.add(cat);
			}
		}
		for (String cat : getFileFuzzerCategories()) {
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
			
		} else {
			String absolutePath = getFuzzerDir().getAbsolutePath() + 
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

    private Database jbroFuzzDB = null;
	private List <String> fuzzerCategories = new ArrayList<>();
	private Map<String, DirCategory> catMap = new HashMap<>();

    private Database getDB() {
    	if (jbroFuzzDB == null) {
    		jbroFuzzDB = new Database();
    	}
    	return jbroFuzzDB;
    }
	
	private void loadFiles() {
        // (Re)Initialise the file based fuzzers
		fuzzerCategories = new ArrayList<>();
		catMap = new HashMap<>();
		
		addFileFuzzers(new File(Constant.getInstance().FUZZER_DIR), null);
		addFileFuzzers(new File(Constant.getZapHome(), Constant.getInstance().FUZZER_DIR), null);
        Collections.sort(fuzzerCategories);
	}

	private void addFileFuzzers(File dir, String parent) {
		boolean addedFuzzer = false;
		File[] files = dir.listFiles();
		DirCategory dirCat;
		if (parent == null) {
			dirCat = new DirCategory("");
		} else if (parent.length() == 0) {
			// Gets rid of the first slash :)
			dirCat = new DirCategory(dir.getName());
		} else {
			dirCat = new DirCategory(parent + " / " + dir.getName());
		}
		if (files != null) {
			for (File file : files) {
				if (file.isDirectory()) {
					if (! file.getName().toLowerCase().startsWith("docs")) {
						// Ignore all files under 'docs.*' folders
						addFileFuzzers(file, dirCat.getName());
					}
				} else if (file.getName().toLowerCase().endsWith(".txt") &&
						! file.getName().startsWith("_") && 
						! file.getName().toLowerCase().startsWith("readme")){
					dirCat.addFuzzer(new FileFuzzer(file));
					addedFuzzer = true;
				}
			}
		}
		if (addedFuzzer) {
			// Dont add 'empty' categories / directories
			this.fuzzerCategories.add(dirCat.getName());
			this.catMap.put(dirCat.getName(), dirCat);
		}
	}

	public List<String> getFileFuzzerCategories() {
		return fuzzerCategories;
	}

	public List <String> getFileFuzzerNames(String category) {
		List <String> fuzzers = new ArrayList<>();
		DirCategory dirCat = this.catMap.get(category);
		if (dirCat != null) {
			for (FileFuzzer ff : dirCat.getFuzzers()) {
				fuzzers.add(ff.getFileName());
			}
		}
		return fuzzers;
	}

	public List<String> getJBroFuzzCategories() {
		String[] allCats = getDB().getAllCategories();
		Arrays.sort(allCats);
		List <String> categories = new ArrayList<>(allCats.length);
		for (String category : allCats) {
			categories.add(JBROFUZZ_CATEGORY_PREFIX + category);
		}
		return categories;
	}

	public List <String> getJBroFuzzFuzzerNames(String category) {
		String jbfCategory = category.substring(JBROFUZZ_CATEGORY_PREFIX.length());
		String [] fuzzers = getDB().getPrototypeNamesInCategory(jbfCategory);
		Arrays.sort(fuzzers);
		List <String> fuzzerNames = new ArrayList<>(fuzzers.length);
		for (String fuzzer : fuzzers) {
			fuzzerNames.add(fuzzer);
		}
		return fuzzerNames;
	}

	public Fuzzer getJBroFuzzer(String name) throws NoSuchFuzzerException {
		return getDB().createFuzzer(getDB().getIdFromName(name), 1);
	}

}
