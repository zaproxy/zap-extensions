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
import java.util.LinkedList;
import java.util.List;

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
	public final static String JBROFUZZ_CATEGORY_PREFIX=ExtensionFuzz.JBROFUZZ_CATEGORY_PREFIX;
	
	public ZestFuzzerDelegate() {
	}

	public File getFuzzerDir() {
		if (this.fuzzerDir == null) {
			fuzzerDir = new File(Constant.getInstance().FUZZER_DIR);
		}
		return fuzzerDir;
	}

	public File getCustomFuzzerDir() {
		if (fuzzerCustomDir == null) {
			fuzzerCustomDir = new File(Constant.getInstance().FUZZER_CUSTOM_DIR);
		}
		return fuzzerCustomDir;
	}
	public File fromFuzzer(Fuzzer fuzzer) throws IOException{
		String fuzzerFileName=fuzzer.getName();
		fuzzerFileName.replace(" ", "_");//TODO not a nice solution
		File copyOfFuzzer=new File(getFuzzerDir().getAbsolutePath()+File.separator+fuzzerFileName);
		FileWriter writer=new FileWriter(copyOfFuzzer);
		while(fuzzer.hasNext()){
			writer.write(fuzzer.next()+"\n");
		}
		writer.close();
		return copyOfFuzzer;
	}
	
	public List<String> getJBroFuzzFuzzerNames(String category){
		return extensionFuzz.getJBroFuzzFuzzerNames(category);
	}
	public List<String> getFileFuzzerNames(String category){
		return extensionFuzz.getFileFuzzerNames(category);
	}

	public List<ZestFuzzerFileDelegate> getAllFuzzFilesAllCat() {
		File[] subDirectory=this.getFuzzerDir().listFiles();
		List<File> filesInDir=new LinkedList<>();
		for(File file: subDirectory){
			if(file.isDirectory()){
				filesInDir = getChildrenFiles(this.getFuzzerDir());
			}
		}
		List<ZestFuzzerFileDelegate> filesDelegateInDir=new LinkedList<>();
		for(File file:filesInDir){
			filesDelegateInDir.add(new ZestFuzzerFileDelegate(file));
		}
		return filesDelegateInDir;
	}

	private List<File> getChildrenFiles(File file) {
		List<File> allFiles = new LinkedList<>();
		for (String filename : fuzzerDir.list()) {
			String absolutePath = file.getAbsolutePath() + File.separator
					+ filename;
			File tmpFile = new File(absolutePath);
			if (tmpFile.isDirectory()) {
				allFiles.addAll(getChildrenFiles(tmpFile));
			} else {
				allFiles.add(tmpFile);
			}
		}
		return allFiles;
	}

	public void addFuzzFile(String cat, ZestFuzzerFileDelegate fuzzFile) {
		try {
			if(fuzzFile.toFuzzerFolder(cat).createNewFile()){
				extensionFuzz.filesAdded();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public FileFuzzer getCustomFileFuzzer(String name){
		return extensionFuzz.getCustomFileFuzzer(name);
	}
	public Fuzzer getJBroFuzzer(String name) throws NoSuchFuzzerException{
		return extensionFuzz.getJBroFuzzer(name);
	}
	
	public List<String> getJBroFuzzCategories(){
		return extensionFuzz.getJBroFuzzCategories();
	}
	public List<String> getCustomFileList(){
		return extensionFuzz.getCustomFileList();
	}
	
	public ZestFuzzerFileDelegate getFuzzerFileDelegate(File file){
		return this.new ZestFuzzerFileDelegate(file);
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
