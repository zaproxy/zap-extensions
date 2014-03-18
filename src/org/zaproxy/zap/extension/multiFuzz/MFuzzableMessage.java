package org.zaproxy.zap.extension.multiFuzz;

import java.util.HashMap;

import org.zaproxy.zap.extension.httppanel.Message;

public abstract class MFuzzableMessage implements org.zaproxy.zap.extension.httppanel.view.FuzzableMessage{
	/**
	 * @return the unmodified Message.
	 */
	public abstract Message getMessage();
	
	/**
	 * @param fuzzString the fuzz string.
	 * @return a Message with the target replaced with the fuzz string.
	 */
	public abstract Message fuzz(HashMap<FuzzLocation, String> replace) throws Exception;
	
	/**
	 * 
	 * @param l the Location which is to be represented by a String
	 * @return a representative name for FuzzLocation l
	 */
	public abstract String representName(FuzzLocation l);
	
	public abstract Message fuzz(String fuzzString) throws Exception;
}
