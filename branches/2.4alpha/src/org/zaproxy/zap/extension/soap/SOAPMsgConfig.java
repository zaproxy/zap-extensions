package org.zaproxy.zap.extension.soap;

import java.util.HashMap;

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
}
