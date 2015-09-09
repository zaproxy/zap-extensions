/*
 * Worker.java
 *
 * Created on 11 November 2005, 20:33
 *
 * Copyright 2007 James Fisher
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */
package com.sittinglittleduck.DirBuster;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.Vector;
import java.util.concurrent.BlockingQueue;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.httpclient.ConnectTimeoutException;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.NoHttpResponseException;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.HeadMethod;

/**
 * This class process workunit and determines if the link has been found or not
 */
public class Worker implements Runnable
{

    private BlockingQueue<WorkUnit> queue;
    private URL url;
    private WorkUnit work;
    private Manager manager;
    private HttpClient httpclient;
    private boolean pleaseWait = false;
    private int threadId;
    private boolean working;
    private boolean stop = false;

    /**
     * Creates a new instance of Worker
     * @param threadId Unique thread id for the worker
     * @param manager The manager class the worker thread reports to
     */
    public Worker(int threadId)
    {
        //get the manager instance
        manager = Manager.getInstance();

        //get the work queue from, the manager
        queue = manager.workQueue;

        //get the httpclient
        httpclient = manager.getHttpclient();

        //set the thread id
        this.threadId = threadId;

    }
    

    /**
     * Run method of the thread
     *
     */
    public void run()
    {

        queue = manager.workQueue;
        while(manager.hasWorkLeft())
        {

            working = false;
            //code to make the worker pause, if the pause button has been presed

            //if the stop signal has been given stop the thread
            if(stop)
            {
                return;
            }

            //this pauses the thread
            synchronized(this)
            {
                while(pleaseWait)
                {
                    try
                    {
                        wait();
                    }
                    catch(InterruptedException e)
                    {
                        return;
                    }
                    catch(Exception e)
                    {
                        e.printStackTrace();
                    }
                }
            }

            HttpMethodBase httpMethod = null;

            try
            {

                work = (WorkUnit) queue.take();
                working = true;
                url = work.getWork();
                int code = 0;

                String response = "";
                String rawResponse = "";
                
                httpMethod = createHttpMethod(work.getMethod(), url.toString());

                //if the work is a head request
                if(work.getMethod().equalsIgnoreCase("HEAD"))
                {
                    code = makeRequest(httpMethod);
                    httpMethod.releaseConnection();

                }
                //if we are doing a get request
                else if(work.getMethod().equalsIgnoreCase("GET"))
                {
                	code = makeRequest(httpMethod);

                    String rawHeader = getHeadersAsString(httpMethod);
                    response = getResponseAsString(httpMethod);
                    
                    rawResponse = rawHeader + response;
                    //clean the response
                    
                    if(Config.parseHTML && !work.getBaseCaseObj().isUseRegexInstead()) {
                    	parseHtml(httpMethod, response);
                    }
                    
                    response = FilterResponce.CleanResponce(response, work);

                    Thread.sleep(10);
                    httpMethod.releaseConnection();
                }

                //if we need to check the against the base case
                if(work.getMethod().equalsIgnoreCase("GET") && work.getBaseCaseObj().useContentAnalysisMode())
                {
                    if(code == HttpStatus.SC_OK)
                    {
                        verifyResponseForValidRequests(code, response, rawResponse);
                    }
                    else if(code == HttpStatus.SC_NOT_FOUND || code == HttpStatus.SC_BAD_REQUEST)
                    {
                    	if (Config.debug) {
                    		System.out.println("DEBUG Worker[" + threadId + "]: " + code + " for: " + url.toString());
                    	}
                    }
                    else
                    {
                    	notifyItemFound(code, response, rawResponse, work.getBaseCaseObj().getBaseCase());
                    }
                }
                /*
                 * use the custom regex check instead
                 */
                else if(work.getBaseCaseObj().isUseRegexInstead())
                {
                    Pattern regexFindFile = Pattern.compile(work.getBaseCaseObj().getRegex());

                    Matcher m = regexFindFile.matcher(rawResponse);

                    if(m.find())
                    {
                        //do nothing as we have a 404
                        if(Config.debug)
                        {
                            System.out.println("DEBUG Worker[" + threadId + "]: Regex matched so it's a 404, " + url.toString());
                        }

                    }
                    else
                    {
                        if(Config.parseHTML)
                        {
                            parseHtml(httpMethod, rawResponse);
                        }
                        
                        notifyItemFound(code, response, rawResponse, work.getBaseCaseObj().getBaseCase());                        
                    }


                }
                //just check the response code
                else
                {
                    //if is not the fail code, a 404 or a 400 then we have a possible
                    if(code != work.getBaseCaseObj().getFailCode() && verifyIfCodeIsValid(code))
                    {
                        if(work.getMethod().equalsIgnoreCase("HEAD"))
                        {
                        	httpMethod = createHttpMethod("GET", url.toString());
                        	int newCode = makeRequest(httpMethod);

                            //in some cases the second get can return a different result, than the first head request!
                            if(newCode != code)
                            {
                                manager.foundError(url, "Return code for first HEAD, is different to the second GET: " + code + " - " + newCode);
                            }

                            //build a string version of the headers
                            rawResponse = getHeadersAsString(httpMethod);

                            if(httpMethod.getResponseContentLength() > 0)
                            {

                                String responseBodyAsString = getResponseAsString(httpMethod);
                                rawResponse = rawResponse + responseBodyAsString;

                                if(Config.parseHTML)
                                {
                                    parseHtml(httpMethod, responseBodyAsString);
                                }
                            }

                            httpMethod.releaseConnection();
                        }


                        if(work.isDir())
                        {
                            manager.foundDir(url, code, rawResponse, work.getBaseCaseObj());
                        }
                        else
                        {
                            manager.foundFile(url, code, rawResponse, work.getBaseCaseObj());
                        }
                    }
                }

                manager.workDone();
                Thread.sleep(20);

            }
            catch(NoHttpResponseException e)
            {
                manager.foundError(url, "NoHttpResponseException " + e.getMessage());
                manager.workDone();
            }
            catch(ConnectTimeoutException e)
            {
                manager.foundError(url, "ConnectTimeoutException " + e.getMessage());
                manager.workDone();
            }
            catch(URIException e)
            {
                manager.foundError(url, "URIException " + e.getMessage());
                manager.workDone();
            }
            catch(IOException e)
            {

                manager.foundError(url, "IOException " + e.getMessage());
                manager.workDone();
            }
            catch(InterruptedException e)
            {
                //manager.foundError(url, "InterruptedException " + e.getMessage());
                manager.workDone();
                return;
            }
            catch(IllegalArgumentException e)
            {

                e.printStackTrace();
                manager.foundError(url, "IllegalArgumentException " + e.getMessage());
                manager.workDone();
            }
            finally
            {
            	if (httpMethod != null){
            		httpMethod.releaseConnection();
            	}
            }
        }

    }
    
    private HttpMethodBase createHttpMethod (String method, String url) {
    	switch (method.toUpperCase()) {
    	case "HEAD":
    		return new HeadMethod(url);	
    	case "GET":
    		return new GetMethod(url);		
    	default:
    		throw new IllegalStateException("Method not yet created");
    	}
    }
     
    private int makeRequest(HttpMethodBase httpMethod) throws HttpException, IOException, InterruptedException {
    	if(Config.debug)
        {
            System.out.println("DEBUG Worker[" + threadId + "]: "+ httpMethod.getName() + " : " + url.toString());
        }

        //set the custom HTTP headers
        Vector HTTPheaders = manager.getHTTPHeaders();
        for(int a = 0; a < HTTPheaders.size(); a++)
        {
            HTTPHeader httpHeader = (HTTPHeader) HTTPheaders.elementAt(a);
            /*
             * Host header has to be set in a different way!
             */
            if(httpHeader.getHeader().startsWith("Host"))
            {
            	httpMethod.getParams().setVirtualHost(httpHeader.getValue());
            }
            else
            {
            	httpMethod.setRequestHeader(httpHeader.getHeader(), httpHeader.getValue());
            }

        }
        httpMethod.setFollowRedirects(Config.followRedirects);

        /*
         * this code is used to limit the number of request/sec
         */
        if(manager.isLimitRequests())
        {
            while(manager.getTotalDone() / ((System.currentTimeMillis() - manager.getTimestarted()) / 1000.0) > manager.getLimitRequestsTo())
            {
                Thread.sleep(100);
            }
        }
        /*
         * Send the request
         */
        int code = httpclient.executeMethod(httpMethod);
        
        if(Config.debug)
        {
            System.out.println("DEBUG Worker[" + threadId + "]: " + code + " " + url.toString());
        }
		return code;
    }

	private boolean verifyIfCodeIsValid(int code) {
		return code != HttpStatus.SC_NOT_FOUND && code != 0 && code != HttpStatus.SC_BAD_GATEWAY;
	}


	private void verifyResponseForValidRequests(int code, String response, String rawResponse) {
		if(Config.debug)
		{
		    System.out.println("DEBUG Worker[" + threadId + "]: Base Case Check " + url.toString());
		}


		//TODO move this option to the Adv options
		//if the response does not match the base case
		Pattern regexFindFile = Pattern.compile(".*file not found.*", Pattern.CASE_INSENSITIVE);

		Matcher m = regexFindFile.matcher(response);

		//need to clean the base case of the item we are looking for
		String basecase = FilterResponce.removeItemCheckedFor(work.getBaseCaseObj().getBaseCase(), work.getItemToCheck());

		if(m.find())
		{
			System.out.println("DEBUG Worker[" + threadId + "]: 404 for: " + url.toString());
		}
		else if(!response.equalsIgnoreCase(basecase))
		{
			notifyItemFound(code, response, rawResponse, basecase);
		}
	}
	
	private void notifyItemFound(int code, String response, String rawResponse, String basecase, String type) {
		if(work.isDir())
		{
		    if(Config.debug)
		    {
		        System.out.println("DEBUG Worker[" + threadId + "]: Found Dir (" + type +")" + url.toString());
		    }
		    //we found a dir
		    manager.foundDir(url, code, response, basecase, rawResponse, work.getBaseCaseObj());
		}
		else
		{
		    //found a file
		    if(Config.debug)
		    {
		        System.out.println("DEBUG Worker[" + threadId + "]: Found File (" + type +")" + url.toString());
		    }
		    manager.foundFile(url, code, response, basecase, rawResponse, work.getBaseCaseObj());
		}
	}
	

	private void notifyItemFound(int code, String response, String rawResponse, String basecase) {
		notifyItemFound(code, response, rawResponse, basecase, "base case");		
	}

	private void parseHtml(HttpMethodBase httpMethod, String response) {
		//parse the html of what we have found

	    Header contentType = httpMethod.getResponseHeader("Content-Type");

	    if(contentType != null)
	    {
	        if(contentType.getValue().startsWith("text"))
	        {
	            manager.addHTMLToParseQueue(new HTMLparseWorkUnit(response, work));
	        }
	    }
		
	}

	private String getResponseAsString(HttpMethodBase httpMethod) throws IOException {		
		Charset chartSet = getCharsetFrom(httpMethod);
		return new String(httpMethod.getResponseBody(), chartSet);
	}

	private Charset getCharsetFrom(HttpMethodBase httpMethod) {
		Charset chartSet;
		
		try {	
			chartSet = Charset.forName(httpMethod.getRequestCharSet());
		} catch (Exception ex) {
			chartSet = Charset.forName("UTF-8");
		}
		return chartSet;
	}

	private String getHeadersAsString(HttpMethodBase httpMethod) {
		Header[] headers = httpMethod.getResponseHeaders();
		
		StringBuilder builder = new StringBuilder(20 * (headers.length +1));
		
		builder.append(httpMethod.getStatusLine());
		builder.append("\r\n");
		
		for (Header header : headers) {
			builder.append(header.getName()).append(": ").append(header.getValue());
			builder.append("\r\n");
		}

		return builder.append("\r\n").toString();
	}

    /**
     * Method to call to pause the thread
     */
    public void pause()
    {
        pleaseWait = true;
    }

    /**
     * Method to call to unpause the thread
     */
    public void unPause()
    {
        pleaseWait = false;
    }

    /**
     * Return a boolean based on if the thread is working
     * @return boolean value about if the thread is working
     */
    public boolean isWorking()
    {
        return working;
    }

    /**
     * Method to call to stop the thread
     */
    public void stopThread()
    {
        this.stop = true;
    }
}
