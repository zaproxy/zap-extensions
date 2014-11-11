package org.zaproxy.zap.extension.soap;

import java.util.HashMap;
import java.util.Set;

import com.predic8.wsdl.BindingOperation;
import com.predic8.wsdl.Definitions;
import com.predic8.wsdl.Port;

/**
 * This class encapsulates all required variables to craft a SOAP request message.
 * @author Albertov91
 *
 */
public class SOAPMsgConfig {

	private Definitions wsdl;
	private int soapVersion = 0;
	private HashMap<String, String> params;
	private Port port;
	private BindingOperation bindOp;
	
	/* Constructors. */
	public SOAPMsgConfig(){
		
	}
	
	public SOAPMsgConfig(Definitions wsdl, int soapVersion, HashMap<String,String> params, Port port, BindingOperation bindOp){
		this.setWsdl(wsdl);
		this.setSoapVersion(soapVersion);
		this.setParams(params);
		this.setPort(port);
		this.setBindOp(bindOp);
	}
	
	/* Custom methods. */
	public boolean isComplete(){
		if (this.wsdl == null || this.soapVersion < 1 || this.soapVersion > 2 || this.params == null || 
				this.port == null || this.bindOp == null) return false;
		else return true;
	}
	
	/* Changes a parameter value given its simple name (it can include namespace prefix). 
	 * Returns true if value has been changed correctly.*/
	public boolean changeParam(String paramName, String paramValue){
		if(paramName == null || paramValue == null) return false;
		String xpath = null;
		Set<String> xpaths = params.keySet();
		if(paramName.contains(":")){
			/* Removes namespace prefix. */
			String[] paramNameParts = paramName.split(":");
			paramName = paramNameParts[paramNameParts.length-1];
		}
		for(String key: xpaths){
			if(key.endsWith("/"+paramName)){
				xpath = key;
				break;
			}
		}
		if (xpath != null){
			params.put(xpath, paramValue);
			return true;
		}else{
			return false;
		}
	}

	/* Getters and Setters. */
	public Definitions getWsdl() {
		return wsdl;
	}

	public void setWsdl(Definitions wsdl) {
		this.wsdl = wsdl;
	}

	public int getSoapVersion() {
		return soapVersion;
	}

	public void setSoapVersion(int soapVersion) {
		this.soapVersion = soapVersion;
	}

	public HashMap<String, String> getParams() {
		return params;
	}

	public void setParams(HashMap<String, String> params) {
		this.params = params;
	}

	public Port getPort() {
		return port;
	}

	public void setPort(Port port) {
		this.port = port;
	}

	public BindingOperation getBindOp() {
		return bindOp;
	}

	public void setBindOp(BindingOperation bindOp) {
		this.bindOp = bindOp;
	}
	
	public boolean equals(SOAPMsgConfig other){
		if(this.getHash() == other.getHash()){
				return true;
		}else{
				return false;
		}
	}
	
	private int getHash(){
		StringBuilder sb = new StringBuilder();
		sb.append("InitialContent"); // Just in case all parameters are null.
		if(this.wsdl != null) sb.append(this.wsdl.getAsString());
		sb.append(this.soapVersion);
		if(params != null){
			for(String value : params.values()){
				sb.append(value);
			}
		}
		if(port != null && port.getAddress() != null) sb.append(this.port.getAddress().getLocation());
		if(bindOp != null) sb.append(bindOp.getName());
		return sb.toString().hashCode();
	}
}
