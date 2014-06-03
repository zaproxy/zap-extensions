package org.zaproxy.zap.extension.soap;

import java.util.ArrayList;
import java.util.HashMap;

import org.parosproxy.paros.network.HttpMessage;

public class ImportWSDL {

	//Dynamic table filled with all SOAP actions detected from multiple WSDL files.
	private HashMap<String, ArrayList<String>> soapActions = new HashMap<String, ArrayList<String>>(); 
	
	//Dynamic table filled with all SOAP requests sended.
	private HashMap<String, ArrayList<HttpMessage>> requestsList = new HashMap<String, ArrayList<HttpMessage>>(); 
	
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
	
	
	public void putAction(String fileName, String opName){
		if (fileName == null || opName == null) return;
		synchronized (this){
			ArrayList<String> opsInFile = soapActions.get(fileName);
			if (opsInFile == null) soapActions.put(fileName, new ArrayList<String>());
			soapActions.get(fileName).add(opName);	
		}	
	}
	
	public void putRequest(String fileName, HttpMessage request){
		if (fileName == null || request == null) return;
		synchronized (this){
			ArrayList<HttpMessage> opsInFile = requestsList.get(fileName);
			if (opsInFile == null) requestsList.put(fileName, new ArrayList<HttpMessage>());
			requestsList.get(fileName).add(request);	
		}	
	}
	
	/* Returns all detected SOAP actions as a fixed bidimensional array. Each row represents a different WSDL file. */
	public synchronized String[][] getSoapActions(){
		String[][] operationsTable = new String[soapActions.size()][];
		int i = 0;
		for(ArrayList<String> ops : soapActions.values()){
			String[] row = new String[ops.size()];
			ops.toArray(row);
			operationsTable[i] = row;
			i++;
		}
		return operationsTable;
	}
	
	/* Returns all SOAP Actions available in the WSDL file explored, given a valid request. */
	public synchronized String[] getFileSoapActions(final HttpMessage request){
		if (requestsList == null || requestsList.size() <= 0) return null;
		/* List of WSDL files. */
		String[] keys = new String[requestsList.size()];
		requestsList.keySet().toArray(keys);
		/* Looks for the file that is referenced by the history reference. */
		for(int i = 0; i < requestsList.size(); i++){
			ArrayList<HttpMessage> index = requestsList.get(keys[i]);
			for(int j = 0; j < index.size(); j++){
				if(index.get(j).equals(request)){
					/* File has been found. */
					String fileName = keys[i];
					ArrayList<String> actions = soapActions.get(fileName);
					String[] actionsList = new String[actions.size()];
					return actions.toArray(actionsList);
				}
			}
		}
		return null;
	}
}
