package org.zaproxy.zap.extension.cmss;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jdom2.Document;

public class PlunginGuesser {
	
	
	/**
	 * 
	****** this is will be modular , each app must have its own plugin
	 */
	
	// I will start with specific wabaaps, CMSs first
	// and joomla first
	public static void joomlaComponentLister(URL url, String componentType){
		try{
			InputStream flux = null;
			if(componentType.compareTo("plugin")==0){
				flux=new FileInputStream("pluginEnum/joomla_plugins.txt"); 
			}
			if(componentType.compareTo("theme")==0){
				flux=new FileInputStream("pluginEnum/joomla_themes.txt"); 
			}
			
			InputStreamReader lecture=new InputStreamReader(flux);
			BufferedReader buff=new BufferedReader(lecture);
			String line;
			while ((line=buff.readLine())!=null){
				//System.out.println(line);
				URL completeUrl = new URL((url.toString()+line).replaceAll(" ", ""));
				//System.out.println(completeUrl.toString());
				HttpURLConnection  con = (HttpURLConnection) completeUrl.openConnection();
				con.setRequestMethod("HEAD");
				//System.out.println(con.getResponseCode());
				if(con.getResponseCode() == HttpURLConnection.HTTP_OK){
					//System.out.println(completeUrl.toString());
					//System.out.println(con.getResponseCode());
					System.out.println(componentType+" : "+line+" exists!!");
					URL rdm = new URL(completeUrl.toString()+"readme.txt");
					//System.out.println(rdm.toString());
					HttpURLConnection  conx = (HttpURLConnection) rdm.openConnection();
					conx.setRequestMethod("HEAD");
					if(conx.getResponseCode() == HttpURLConnection.HTTP_OK){
						System.out.println("------------> readme exists !!");
					}
				}
			}
			buff.close(); 
		}		
		catch (Exception e){
			System.out.println(e.toString());
		}
	}
	
	
	
	public static void prepareJoomlaPluginDB(){
		//pending
	}
	
	
	// using fuzzdb from googlecode.com 
	// j'ai remarque que la base de wp scan est plus riche avec une difference de format 
	// celle de fuzz contient le chemin du plugin a partir de l'url : /component/nom_plugin ..
	// celle de wp scan contirnt que le nom
	// donc il faut combiner combiner (-_-)
	
	// I noted that wpscan files contain better list of plugins 
	// so TODO: decide if we continue to use fuzzdb or use wpscan files or combine
	
	public static void getJoomlaPluginDB() throws IOException{
		URL website = new URL("https://fuzzdb.googlecode.com/svn/trunk/Discovery/PredictableRes/CMS/joomla_plugins.fuzz.txt");
	    ReadableByteChannel rbc = Channels.newChannel(website.openStream());
	    @SuppressWarnings("resource") 
		FileOutputStream fos = new FileOutputStream("pluginEnum/joomla_plugins.txt");
	    fos.getChannel().transferFrom(rbc, 0, Long.MAX_VALUE);
	}
	public static void getJoomlaThemeDB() throws IOException{
		URL website = new URL("https://fuzzdb.googlecode.com/svn/trunk/Discovery/PredictableRes/CMS/joomla_themes.fuzz.txt");
	    ReadableByteChannel rbc = Channels.newChannel(website.openStream());
	    @SuppressWarnings("resource") 
		FileOutputStream fos = new FileOutputStream("pluginEnum/joomla_themes.txt");
	    fos.getChannel().transferFrom(rbc, 0, Long.MAX_VALUE);
	}
	
	
	
	
	
	//wordpress part
	public static void wordpressComponentLister(URL url, String componentType){
		try{
			InputStream flux = null;
			if(componentType.compareTo("plugin")==0){
				flux=new FileInputStream("pluginEnum/wp_plugins.txt"); 
			}
			if(componentType.compareTo("theme")==0){
				flux=new FileInputStream("pluginEnum/wp_themes.txt"); 
			}
			
			InputStreamReader lecture=new InputStreamReader(flux);
			BufferedReader buff=new BufferedReader(lecture);
			String line;
			while ((line=buff.readLine())!=null){
				//System.out.println(line);
				URL completeUrl = new URL((url.toString()+line).replaceAll(" ", ""));
				//System.out.println(completeUrl.toString());
				HttpURLConnection  con = (HttpURLConnection) completeUrl.openConnection();
				con.setRequestMethod("HEAD");
				//System.out.println(con.getResponseCode());
				if(con.getResponseCode() == HttpURLConnection.HTTP_OK){
					//System.out.println(completeUrl.toString());
					//System.out.println(con.getResponseCode());
					System.out.println(componentType+" : "+line+" exists!!");
					URL rdm = new URL(completeUrl.toString()+"readme.txt");
					//System.out.println(rdm.toString());
					HttpURLConnection  conx = (HttpURLConnection) rdm.openConnection();
					conx.setRequestMethod("HEAD");
					if(conx.getResponseCode() == HttpURLConnection.HTTP_OK){
						System.out.println("------------> readme exists !!");
						Document doc = (Document) conx.getContent();
						Pattern p = Pattern.compile("Stable tag: (.+)");
						Matcher m = p.matcher(doc.toString());
    					while(m.find()){
    						
    						System.out.println("  version :   "+m.group(0));
    						
    					}
					}
				}
			}
			buff.close(); 
		}		
		catch (Exception e){
			System.out.println(e.toString());
		}
	}	

	public static void getWordpressPluginDB() throws IOException{
		URL website = new URL("https://fuzzdb.googlecode.com/svn/trunk/Discovery/PredictableRes/CMS/wp_plugins.fuzz.txt");
	    ReadableByteChannel rbc = Channels.newChannel(website.openStream());
	    @SuppressWarnings("resource") 
		FileOutputStream fos = new FileOutputStream("pluginEnum/wp_plugins.txt");
	    fos.getChannel().transferFrom(rbc, 0, Long.MAX_VALUE);
	}
	public static void getWordpressThemeDB() throws IOException{
		URL website = new URL("https://fuzzdb.googlecode.com/svn/trunk/Discovery/PredictableRes/CMS/wp_themes.fuzz.txt");
	    ReadableByteChannel rbc = Channels.newChannel(website.openStream());
	    @SuppressWarnings("resource") 
		FileOutputStream fos = new FileOutputStream("pluginEnum/wp_themes.txt");
	    fos.getChannel().transferFrom(rbc, 0, Long.MAX_VALUE);
	}
	
	// drupal part 
	public static void drupalComponentLister(URL url, String componentType){
		try{
			InputStream flux = null;
			if(componentType.compareTo("plugin")==0){
				flux=new FileInputStream("pluginEnum/drupal_plugins.txt"); 
			}
			if(componentType.compareTo("theme")==0){
				flux=new FileInputStream("pluginEnum/drupal_themes.txt"); 
			}
			
			InputStreamReader lecture=new InputStreamReader(flux);
			BufferedReader buff=new BufferedReader(lecture);
			String line;
			while ((line=buff.readLine())!=null){
				//System.out.println(line);
				URL completeUrl = new URL((url.toString()+line).replaceAll(" ", ""));
				//System.out.println(completeUrl.toString());
				HttpURLConnection  con = (HttpURLConnection) completeUrl.openConnection();
				con.setRequestMethod("HEAD");
				//System.out.println(con.getResponseCode());
				if(con.getResponseCode() == HttpURLConnection.HTTP_OK){
					//System.out.println(completeUrl.toString());
					//System.out.println(con.getResponseCode());
					System.out.println(componentType+" : "+line+" exists!!");
					URL rdm = new URL(completeUrl.toString()+"readme.txt");
					//System.out.println(rdm.toString());
					HttpURLConnection  conx = (HttpURLConnection) rdm.openConnection();
					conx.setRequestMethod("HEAD");
					if(conx.getResponseCode() == HttpURLConnection.HTTP_OK){
						System.out.println("------------> readme exists !!");
					}
				}
			}
			buff.close(); 
		}		
		catch (Exception e){
			System.out.println(e.toString());
		}
	}
	
	public static void getDrupalPluginDB() throws IOException{
		URL website = new URL("https://fuzzdb.googlecode.com/svn/trunk/Discovery/PredictableRes/CMS/drupal_plugins.fuzz.txt");
	    ReadableByteChannel rbc = Channels.newChannel(website.openStream());
	    @SuppressWarnings("resource") 
		FileOutputStream fos = new FileOutputStream("pluginEnum/drupal_plugins.txt");
	    fos.getChannel().transferFrom(rbc, 0, Long.MAX_VALUE);
	}
	public static void getDrupalThemeDB() throws IOException{
		URL website = new URL("https://fuzzdb.googlecode.com/svn/trunk/Discovery/PredictableRes/CMS/drupal_themes.fuzz.txt");
	    ReadableByteChannel rbc = Channels.newChannel(website.openStream());
	    @SuppressWarnings("resource") 
		FileOutputStream fos = new FileOutputStream("pluginEnum/drupal_themes.txt");
	    fos.getChannel().transferFrom(rbc, 0, Long.MAX_VALUE);
	}
	
}
