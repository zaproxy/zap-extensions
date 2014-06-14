package org.zaproxy.zap.extension.soap;

import java.util.ArrayList;
import java.util.HashMap;

import org.parosproxy.paros.network.HttpMessage;

public class ImportWSDL {

	//Dynamic chart filled with all SOAP actions detected from multiple WSDL files.
	private HashMap<Integer, ArrayList<String>> soapActions = new HashMap<Integer, ArrayList<String>>(); 
	
	//Dynamic chart filled with all sended SOAP requests.
	private HashMap<Integer, ArrayList<HttpMessage>> requestsList = new HashMap<Integer, ArrayList<HttpMessage>>(); 
	
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
	
	
	public void putAction(int wsdlKey, String opName){
		if (wsdlKey < 0 || opName == null) return;
		synchronized (this){
			ArrayList<String> opsInFile = soapActions.get(wsdlKey);
			if (opsInFile == null) soapActions.put(wsdlKey, new ArrayList<String>());
			soapActions.get(wsdlKey).add(opName);	
		}	
	}
	
	public void putRequest(int wsdlKey, HttpMessage request){
		if (wsdlKey < 0 || request == null) return;
		synchronized (this){
			ArrayList<HttpMessage> opsInFile = requestsList.get(wsdlKey);
			if (opsInFile == null) requestsList.put(wsdlKey, new ArrayList<HttpMessage>());
			requestsList.get(wsdlKey).add(request);	
		}	
	}
	
	/* Returns all detected SOAP actions as a fixed bidimensional array. Each row represents a different WSDL file. */
	public synchronized String[][] getSoapActions(){
		String[][] operationsChart = new String[soapActions.size()][];
		int i = 0;
		for(ArrayList<String> ops : soapActions.values()){
			String[] row = new String[ops.size()];
			ops.toArray(row);
			operationsChart[i] = row;
			i++;
		}
		return operationsChart;
	}
	
	/* Returns all SOAP Actions available in the WSDL source explored, given a valid request. */
	public synchronized String[] getSourceSoapActions(final HttpMessage request){
		if (requestsList == null || requestsList.size() <= 0) return null;
		/* List of WSDL files. */
		Integer[] keys = new Integer[requestsList.size()];
		requestsList.keySet().toArray(keys);
		/* Looks for the file that is referenced by the history reference. */
		for(int i = 0; i < requestsList.size(); i++){
			ArrayList<HttpMessage> index = requestsList.get(keys[i]);
			for(int j = 0; j < index.size(); j++){
				if(index.get(j).equals(request)){
					/* File has been found. */
					int key = keys[i];
					ArrayList<String> actions = soapActions.get(key);
					String[] actionsList = new String[actions.size()];
					return actions.toArray(actionsList);
				}
			}
		}
		return null;
	}
}
