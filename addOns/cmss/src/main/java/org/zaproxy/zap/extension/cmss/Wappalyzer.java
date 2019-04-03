package org.zaproxy.zap.extension.cmss;


import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

public class Wappalyzer {
	
	
	// this contain apps.json content 
	static private JSONObject jsonObject = new JSONObject();
	
	/**
	 * get JsonObject from json db file (apps.json)
	 * @throws Exception
	 */
    public static void initJsonObject() throws Exception {
    	JSONParser parser = new JSONParser();
        try {
            Object obj = parser.parse(new FileReader("resources/fastGuess/apps.json"));
            jsonObject = (JSONObject) obj;         
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        }      	
    }

    /**
     * 
     * TODO: finalize and clean the code 
     * 
     * analyses the given url to check possible apps 
     * @param url
     * @throws Exception 
     */
    public static ArrayList<String> analyse(URL url, ArrayList<String> whatToFingerPrint) throws Exception {
    	ArrayList<String> detectedApps = new ArrayList<String>() ;
    	WebPage wp = new WebPage(url);
    	ArrayList<String> applist = new ArrayList<String>() ;
    	ArrayList<String> categlist = new ArrayList<String>() ;  
    	JSONParser parser = new JSONParser();
    	initJsonObject();// must take place here before the next instruction
   	    ArrayList<String> categTofIngerPrint = categoryNameToNumber(whatToFingerPrint);
        Object obj = parser.parse(new FileReader("resources/fastGuess/apps.json"));
        jsonObject = (JSONObject) obj;
        
        JSONObject apps =  (JSONObject) jsonObject.get("apps");
            
        /**
        * here we apply hasApp method , results are printed for the moment  
        */
            
        // ici il faut trouver une maniere plus optimale pour la recherche 
        // le suivant est un parcourt sequentiel du fichier apps.json 
        for(int i = 0; i< apps.keySet().size();i++){
        	String appName = (apps.keySet().toArray())[i].toString();
        	String cats = ((JSONObject)apps.get(appName)).get("cats").toString();
        	//System.out.println(appName);
        	System.out.println(cats.replace("[", "").replace("]", ""));
        	if(categTofIngerPrint.contains(cats.replace("[", "").replace("]", ""))){
        		System.out.println(cats+" *** "+appName);
            	if (hasApp((JSONObject)apps.get(appName),wp)){
            		//System.out.println("---------->"+appName);
            		detectedApps.add(appName.toLowerCase());
            		//break;
            	}
        	} 	
        }
        /**
        * ****************************************************************
        */
        applist= new ArrayList<String>() ;
        for (int i = 0 ; i<apps.keySet().size(); i++){
            applist.add((apps.keySet().toArray())[i].toString());
            //System.out.println(applist.get(i)+"   "+i);
        }
            
        JSONObject categories =  (JSONObject) jsonObject.get("categories");
        categlist = new ArrayList<String>() ;
        for (int i = 0 ; i<categories.keySet().size(); i++){
            categlist.add((categories.keySet().toArray())[i].toString());
            //System.out.println(categlist.get(i));
        } 
        return detectedApps;
    }
    
    
    /**
     * Answers if the web app of the given web page (wp) has for type : app.name (the given app) 
     * @param app : JSON object representing a web app (from the json file)
     * @param wp : the web page to analyze 
     * @return
     * @throws IOException
     */
    public static boolean hasApp(JSONObject app, WebPage wp) throws IOException{
    	System.out.println("has apps ");
    	boolean result = false;
    	Document HTML = wp.getDocument();
    	String url = wp.getURL().toString();
    	
    	String[] keys1 = {"url","html","script"}, 
    			keys2={"headers","meta"}; // these two are couples of name:value
    	
    	for(String key : keys1){
    		//System.out.println(key);
    		// NOTE1: for those web apps : jquery, jquery UI and Magento 
			// the format of 'script' attribute is different to the others
			// an exception occurs when you try to cast its regex field to string
			// for the moment I use try catch to skip it, but TODO : make 
			// a special treatment for that :) 
    		//
    		// NOTE2: for those apps : Chartbeat, Zabbix and DreamWeaver
    		// this part of regex : (\\) inhtml field causes problem, 
    		// TODO study this in depth
    		// for the moment I skip this by try catch in the line :
    		// Pattern p = Pattern.compile(regex);
    		
    		String pattern = null;
    		try{
    			pattern = (String) app.get(key);
    		}
    		catch(Exception e){
    			e.printStackTrace();
    		}
    		if(pattern != null){
    			// NOTE: that there is differences between
    			// java regex and javascript ones TODO study that in depth
    			String[] regexes = pattern.split("\\\\;"); 
    			for(String regex:regexes){				
    		    				
    				//System.out.println(regex);
    				
    				// I'm trying catch to skip regex problem that I have 
    				// described above TODO if problem resolved modify it to
    				// Pattern p = Pattern.compile(regex);
    				Pattern p = null;
    				try{
    					p = Pattern.compile(regex);
    				}
    				catch(PatternSyntaxException e){
    					e.printStackTrace();
    				}
    				
    				if (p!=null){ // this will be removed once regex problem resolved
    				if(key.compareTo("url")==0){
    					Matcher m = p.matcher(url);
    					if (m.find()) result=true;
    					m.reset();
    					while(m.find()){
    						System.out.println("regex   :   "+regex);
    						System.out.println(key+"   :   "+m.group(0));	
    					}
    				}
    				if(key.compareTo("html")==0){
    					Matcher m = p.matcher(HTML.outerHtml());
    					if (m.find()) result=true;
    					m.reset();
    					while(m.find()){
    						System.out.println("regex   :   "+regex);
    						System.out.println(key+"   :   "+m.group(0));
    					}           
    				}
    				if(key.compareTo("script")==0){
    					for(Element script:wp.getScriptNodes()){
    						Matcher m = p.matcher(""+script.toString());
    						if (m.find()) result=true;
    						m.reset();
    						while(m.find()){
    							System.out.println("regex   :   "+regex);
    							System.out.println(key+"   :   "+m.group(0));
    						}      
    					}
    				}
    				}// this will be removed once regex problem resolved
    			} 		
    		}
    	}
    	for(String key : keys2){
    		//System.out.println(key);
    		JSONObject listHorM = (JSONObject) app.get(key);
    		if(listHorM != null){
    			
    			for(Object name:listHorM.keySet()){
    				String pattern = (String) listHorM.get(name);
    				String[] regexes = pattern.split("\\\\;");
    				for(String regex:regexes){
        				Pattern p = Pattern.compile(regex);
        				if(key.compareTo("headers")==0){
        					//System.out.println("name == "+name);
        					if(wp.getHeaders().get(name) != null){
        							String HeaderContent = wp.getHeaders().get(name).toString(); // <---
        							Matcher m = p.matcher(HeaderContent);
        							if (m.find()) result=true;
        							m.reset();
                					while(m.find()){
                						System.out.println("regex   :   "+regex);
                						System.out.println(HeaderContent);
                						System.out.println(name+"   :   "+m.group(0));
                					}     
        					}
        						
        				}
        				if(key.compareTo("meta")==0){
        					
        					
        					if(wp.getMetaNodes().get(name) != null){
    							String metaContent = wp.getMetaNodes().get(name).toString(); // <---
    							Matcher m = p.matcher(metaContent);
    							if (m.find()) result=true;
    							m.reset();
            					while(m.find()){
            						System.out.println("regex   :   "+regex);
            						System.out.println(metaContent);
            						System.out.println(name+"   :   "+m.group(0));
            					}     
        					}
        					
        					
        					/*
        					Map<String, String> metaMap = wp.getMetaNodes();
        					Set<String> names = wp.getMetaNodes().keySet();
        					for(String metaName : names){
        						String content = metaMap.get(metaName);
        						Matcher m = p.matcher(content);
        						if (m.find()) result=true;
        						m.reset();
        						while(m.find()){
        							System.out.println("regex   :   "+regex);
        							System.out.println(content);
        							System.out.println(metaName+"   :   "+m.group(0));
        						} 
        					}
        					*/
        				}
    				}
    			}  				
    		}
    	}
    	
    	return result;
    }
    
    
    
    /**
     * downloads apps.json from wappalyzer GIT repo check wappalyzer wiki 
     * ------>TODO  similar method to prepare BlinElephant files in xml (this is actually in python)
     * @throws IOException
     */
  
    public static void bddUpdate() throws IOException{
		URL website = new URL("https://raw.github.com/ElbertF/Wappalyzer/master/share/apps.json");
	    ReadableByteChannel rbc = Channels.newChannel(website.openStream());
	    @SuppressWarnings("resource")
		FileOutputStream fos = new FileOutputStream("resources/fastGuess/apps.json");
	    fos.getChannel().transferFrom(rbc, 0, Long.MAX_VALUE);
    }
    
    
    public static ArrayList<String> categoryNameToNumber(ArrayList<String> nameList){
    	ArrayList<String> result = new ArrayList<String>();
    	JSONObject categories =  (JSONObject) jsonObject.get("categories");
    	for (int i = 0 ; i<categories.keySet().size(); i++){
    		String key = (categories.keySet().toArray())[i].toString();		
        	//System.out.println(key+"  "+catNumber);
        	String categName = (String) categories.get(key);
    		for (String catName:nameList){
        		if(categName.compareTo(catName)==0){
        			result.add(key);
        			System.out.println(key +" "+ catName);
        		}
        	}		
        }
    	return result;
    }
    
    
    /*
    public static String[] preparePatterns(JSONObject app){
    	String[] regexes = new String[0];
    	String[] keys1 = {"url","html","script"}, keys2={"headers","meta"};
    	for(String key : keys1){
    		String pattern = (String) app.get(key);
    		if(pattern != null){
    			System.out.println(key+" = "+pattern);
    			regexes = pattern.split("\\\\;");
    			
    			System.out.println(regexes[0]);
    			System.out.println(regexes[1]);
 
    			String chaine = "Test regex Java pour <balise1>Wikibooks</balise1> francophone. Java";
                Pattern p = Pattern.compile("(.*) Java");
                Matcher m = p.matcher(chaine);
                while(m.find())
                        System.out.println(m.group(1)+"  "+m.group(0));

    		}
    	}
    	return regexes;
    }
    */
}