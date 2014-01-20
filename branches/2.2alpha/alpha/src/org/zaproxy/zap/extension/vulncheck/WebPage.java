package org.zaproxy.zap.extension.vulncheck;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

/**
 * abstraction class of a web page 
 * @author abdelhadi
 *
 */
public class WebPage {
	
	private URL url ;
	private Document HTMLDoc ;
	private Elements scripts = new Elements();
	private Map<String, List<String>> headers;
	private Map<String, String> metas = new HashMap<String, String>(); 
	
	/**
	 * 
	 * @return the web page url 
	 */
	public URL getURL(){
		return this.url;
	}
	/**
	 * 
	 * @return HTML document of the target web page 
	 * @throws IOException
	 */
	public Document getDocument() throws IOException{
		getHTML(this.url);
		return this.HTMLDoc;
	}
	
	/**
	 * 
	 * @return all HTML script nodes in the target HTML document as DOM elements 
	 * @throws IOException
	 */
	public Elements getScriptNodes() throws IOException{
		getScriptNodes(this.url);
		return this.scripts;
	}
	
	/**
	 * 
	 * @return MapList of the target HTTP headers
	 * @throws IOException
	 */
	public Map<String, List<String>> getHeaders() throws IOException{
		getHTTPHeaders();
		return this.headers;
	}
	
	/**
	 * 
	 * @return List of all HTML meta nodes of the target web page
	 * @throws IOException
	 */
	public Map<String, String> getMetaNodes() throws IOException{
		getMetaNodes(url);
		return this.metas;
	}
	
	/**
	 * Constructor initialize the target web page url and HTML document
	 * @param url
	 * @throws IOException
	 */
	public WebPage(URL url) throws IOException{
		this.HTMLDoc = getHTML(url);
		this.url = url;
	}
	
	/**
	 * TODO re implement it with no additional connexion 
	 * @param url
	 * @return
	 * @throws IOException
	 */
	private static Document getHTML(URL url) {
		try {
			if(! VulCheckUtils.checkIfExist(url)) return null;
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		Document doc = null;
		while(doc == null){
			
			try{
				
				doc = Jsoup.connect(url.toString()).userAgent("Mozilla").timeout(7000).get();
			}
			catch(Exception e){
				e.printStackTrace();
			}
		}
		return doc;
	}
	
	/**
	 * Requests the target for HTTP headers 
	 * @throws IOException
	 */
	private  void getHTTPHeaders() throws IOException{
		URLConnection conn = null;
		while(conn==null){
			try{
				conn = this.url.openConnection();
			}
			catch(Exception e){
				e.printStackTrace();
			}
		}
		//get all headers
		headers = conn.getHeaderFields();
		/*for (Map.Entry<String, List<String>> entry : map.entrySet()) {
			System.out.println("Key : " + entry.getKey() + 
	                 " ,Value : " + entry.getValue());
		}*/
		
		/*//get header by 'key'
		String server = conn.getHeaderField("Server");*/
		
	}
	
	/**
	 * Extracts script nodes from web page HTML document 
	 * @param url
	 * @throws IOException
	 */
	private void getScriptNodes(URL url) throws IOException{
		
		//Document doc = getHTML(url);// this required another connexion
			
        Elements scripts = HTMLDoc.select("script");
        
        
        for (int i=0;i<scripts.size();i++){

        	Element script = scripts.get(i);
        	
        	if(script.hasAttr("src")){
        		//System.out.println("script = "+scripts.get(i)+"");
        		this.scripts.add(script);
        	}
            //System.out.println("-----------------------");
        }
        
	}
	

	/**
	 * Extracts meta nodes from web page HTML document 
	 * @param url
	 * @throws IOException
	 */
	@SuppressWarnings("null")
	private void getMetaNodes(URL url) throws IOException{
		
		//Document doc = getHTML(url);// this required another connexion
        Elements metas = HTMLDoc.select("meta");      
   
        for (int i=0;i<metas.size();i++){
        	Element meta = metas.get(i);

        	if(meta.hasAttr("name") && meta.hasAttr("content")){
        		//System.out.println("meta = "+metas.get(i)+"");
        		this.metas.
        		put(meta.
        		attr("name"), 
        		meta.attr("content"));
        	}
            //System.out.println("-----------------------");
        }
	}	
}
