package org.zaproxy.zap.extension.soap;

import java.util.ArrayList;
import java.util.HashMap;

public class ImportWSDL {

	//Dynamic table filled with all SOAP operations detected from multiple WSDL files.
	private HashMap<String, ArrayList<String>> soapOperations = new HashMap<String, ArrayList<String>>(); 
	
	private volatile static ImportWSDL singleton = null;
	
	private ImportWSDL(){
		
	}
	
	public static ImportWSDL getInstance(){
		if (singleton == null){
			synchronized (ImportWSDL.class){
				if (singleton == null){
					singleton = new ImportWSDL();
				}
			}
		}
		return singleton;
	}
	
	
	public void putOperation(String fileName, String opName){
		if (fileName == null || opName == null) return;
		synchronized (this){
			ArrayList<String> opsInFile = soapOperations.get(fileName);
			if (opsInFile == null) soapOperations.put(fileName, new ArrayList<String>());
			soapOperations.get(fileName).add(opName);	
		}	
	}
	
	/* Returns all detected SOAP operations as a fixed bidimensional array. Each row represents a different WSDL file. */
	public synchronized String[][] getSoapOperations(){
		String[][] operationsTable = new String[soapOperations.size()][];
		int i = 0;
		for(ArrayList<String> ops : soapOperations.values()){
			String[] row = new String[ops.size()];
			ops.toArray(row);
			operationsTable[i] = row;
			i++;
		}
		return operationsTable;
	}
}
