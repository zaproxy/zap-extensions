package org.zaproxy.zap.extension.vulncheck;

import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;


public class VulnChecker {
	/**
	 * Gets CVE from cvedetails.com
	 * --> there is no API, so I parse HTML to get CVEs
	 * @param appName
	 * @param version
	 * @return
	 */
	
	public static String getCve(String appName, String version){
		//TODO manage the case where the appName is a vendor name eg: Drupal
		String result = "";
		URL url = null;
		try{
			Elements elt = new org.jsoup.select.Elements();
			int numPage = 1 ; 
			String link = "";
			while(elt.size() == 0 || link.contains("/vendor/")){
				url = new URL("http://www.cvedetails.com/product-list/firstchar-"+appName.toUpperCase().charAt(0)+"/page-"+numPage+"/");
				WebPage wp = new WebPage(url);
				org.jsoup.nodes.Document doc = wp.getDocument();
				elt = doc.getElementsMatchingOwnText(appName);
				//System.out.println(elt);
				numPage++;
				link = elt.attr("href");
			}
			//System.out.println(numPage);
			//System.out.println(link);
			//String productId = link.split("/")[4]; //actualy this is not needed for the moment
			//System.out.println(productId);
			WebPage wp2 = new WebPage(new URL(link));
			org.jsoup.nodes.Document doc2 = wp2.getDocument();
			Elements elt2 = doc2.getElementsMatchingOwnText("Browse all versions");
			String link2 = elt2.attr("href");
			//System.out.println("link2 = "+link2);
			
			Elements elt3 = new org.jsoup.select.Elements();
			int j = 1;
			while(elt3.size() == 0){
				/*System.out.println("---> http://www.cvedetails.com/"
						+link2.split("/")[0]+"/"+link2.split("/")[1]+"/"+link2.split("/")[2]+"/"+link2.split("/")[3]
								+"/"+j+"/"+link2.split("/")[5]);*/
				WebPage wp3 = new WebPage(new URL("http://www.cvedetails.com/"
						+link2.split("/")[0]+"/"+link2.split("/")[1]+"/"+link2.split("/")[2]+"/"+link2.split("/")[3]
								+"/"+j+"/"+link2.split("/")[5]));
				org.jsoup.nodes.Document doc3 = wp3.getDocument();
				elt3 = doc3.getElementsMatchingText(version)
						.parents();
				j++;
			}
			
			//System.out.println("elt3 = "+elt3);
			org.jsoup.nodes.Element link3 = elt3.get(elt3.size()-1);
			String link4 = link3.getElementsMatchingOwnText("Details").get(0).attr("href");
			String versionCode = link4.split("/")[2];
			//System.out.println("version code ="+versionCode);
			
			/*
			WebPage json = new WebPage(new URL("http://www.cvedetails.com/json-feed.php?numrows=30&product_id="+productId+"&version_id="+version+""));
			org.jsoup.nodes.Document jsonfile = json.getDocument();
			System.out.println(jsonfile.toString());
			*/
			
			InputStream is = VulCheckUtils.getFileFromUrl(new URL("http://www.cvedetails.com/json-feed.php?numrows=30&version_id="+versionCode+""));
			JSONParser parser = new JSONParser();
		
	        @SuppressWarnings("resource")
			String str = new Scanner(is,"UTF-8").useDelimiter("\\A").next();
	 
			//System.out.println(str);
	        try {
	            Object obj = parser.parse(str);
	            JSONArray jsonObjects = (JSONArray) obj;
	            //System.out.println(jsonObjects);
	            for(@SuppressWarnings("unused") Object jsonObject:jsonObjects){
	            	JSONObject json = (JSONObject) jsonObject;
	            	for(int i = 0 ; i<json.keySet().size(); i++){
	            		String key = (json.keySet().toArray())[i].toString();
	            		String content = (String) json.get(key);
	            		result = result.concat(key+" : "+content+"\n");
	            	}
	            	result = result.concat("--------------------------\n");
	            }
	        } catch (ParseException e) {
	            e.printStackTrace();
	        }   
			
		}
		catch(Exception e){
			e.printStackTrace();
		}
		return result;
	}
	/**
	 * Give a list of results appearing in the first result page for the key 
	 * word in packetstormsecurity.org
	 * @param appName
	 * @param version
	 * @return
	 * @throws Exception
	 */
	public static ArrayList<String> fromPacketStorm (String appName, String version) throws Exception{
		// TODO extend this to  fetch all result pages, currently it print only the 1st page
		ArrayList<String> res = new ArrayList<String>();
		
		URL url = new URL("http://packetstormsecurity.org/search/files/?q="+appName+"&s=files");
		
	 	WebPage wp = new WebPage(url);
		Document document = wp.getDocument();
	  
		//System.out.println(document);
		if(( document.text().contains("Your Request Returned Nothing of Interest"))){
			System.out.println("No Results Found in packetstormsecurity.org");
			
		}else{
			Elements elts = document.getElementsByAttributeValue("class", "ico text-plain");
			for(Element elt:elts){
				Pattern p = Pattern.compile("<a class=\"ico text-plain\" href=\"(.+)\" title=\"Size: (.+?) KB\">(.*)</a>");
				Matcher m = p.matcher(elt.toString());
				if(m.find()){		
						String href = elt.attr("href");
						res.add(href);
					}
			}
			System.out.println("dad");
		}
		return res;
	}
	/**
	 * Give a list of securiteam.com search links for the key word introduced
	 * @param appName
	 * @param version
	 * @return
	 * @throws Exception
	 */
	public static ArrayList<String> fromSecuritiTeam(String appName, String version)throws Exception{
		ArrayList<String> results = new ArrayList<String>();
		URL url = new URL("http://www.securiteam.com/cgi-bin/htsearch?words="+appName+"+"+version);
		
		WebPage wp = new WebPage(url);
		Document doc = wp.getDocument();
		if(doc.outerHtml().contains("No matches were found for")){
			System.out.println("No Results Found");
			
		}else{
			//System.out.println(doc.getElementsByTag("dl"));
			for( Element elt : doc.getElementsByTag("dl") ){
				String link = elt.getElementsByTag("a").get(0).attr("href");
				// for the moment i return just links 
				System.out.println(link);
				results.add(link+"\n");
				/*wp = new WebPage(new URL(link));
				doc = wp.getDocument();
				for(Element e:doc.getAllElements()){
					
				}
				String fields = doc.getElementsMatchingOwnText("Vulnerable Systems:").get(0).parent().text();
				System.out.println(fields.replaceAll("Protect your website!.*vulnerability-scanner", ""));
				*/
			}
		}
		return results;
	}
}
