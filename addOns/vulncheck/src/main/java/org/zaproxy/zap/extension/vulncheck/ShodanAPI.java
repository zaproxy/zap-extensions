package org.zaproxy.zap.extension.vulncheck;

import java.io.IOException;
import java.net.URL;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.jsoup.Jsoup;


public class ShodanAPI {
	private static String baseURL = "http://www.shodanhq.com/api/";
	private static String APIKey = "FHGq7Ki04Nj0T68T2XZyMYd3YOPe8Ems";
	/**
	 * General-purpose function to create web requests to SHODAN.
	 * @param function : name of the function you want to execute
	 * @param params : parameters for the function
	 * @return A JSON object containing the function's results
	 * @throws IOException
	 * @throws ParseException
	 */
	public static JSONObject request(String function, String params) throws IOException, ParseException{
		URL url = null;
		try{
			//URLEncoder.encode(  "ISO-8859-1")
			 url = new URL(baseURL+function+"?"+params
					 +"&key="+APIKey);
			 
			 System.out.println(url.toString());
		}
		catch(Exception e){
			//e.printStackTrace();
			System.out.println("connection failed");
		}
		
		org.jsoup.nodes.Document doc =  Jsoup.connect(url.toString()).get();
        JSONParser jsonParser = new JSONParser();
        JSONObject object = (JSONObject) jsonParser.parse(doc.text());
		System.out.println(object);
		return object;
	}
	/**
	 * Returns the total number of search results for the query.
	 * @param query
	 * @return
	 * @throws IOException
	 * @throws ParseException
	 */
	public static JSONObject count(String query) throws IOException, ParseException{
		return request("count", "q="+query);
	}
	/**
	 * Return a break-down of all the countries and cities that the results for
        the given search are located in.
	 * @param query
	 * @return
	 * @throws IOException
	 * @throws ParseException
	 */
	public static JSONObject locations(String query) throws IOException, ParseException{
		return request("locations", "q="+query);
	}
	/**
	 * Determine the software based on the banner.
	 * @param banner: HTTP banner
	 * @return A list of software that matched the given banner.
	 * @throws IOException
	 * @throws ParseException
	 */
	public static JSONObject fingerprint(String banner) throws IOException, ParseException{
		return request("fingerprint", "banner="+banner);
	}
	/**
	 * Get all available information on an IP.
	 * @param ip : IP of the computer
	 * @return  All available information SHODAN has on the given IP,
        subject to API key restrictions.
	 * @throws IOException
	 * @throws ParseException
	 */
	public static JSONObject host(String ip) throws IOException, ParseException{
		return request("host", "ip="+ip);
	}
	/**
	 * @return Information about the current API key, such as a list of add-ons
        and other features that are enabled for the current user's API plan.
	 * @throws IOException
	 * @throws ParseException
	 */
	public static JSONObject info() throws IOException, ParseException{
		return request("info", "");
	}
	/**
	 * Search the SHODAN database.
	 * @param query : search query; identical syntax to the website
	 * @param nPages : page number of the search results 
	 * @param nResults : number of results to return
	 * @param offset : search offset to begin getting results from
	 * @return A dictionary with 3 main items: matches, countries and total.
        Visit the website for more detailed information.
	 * @throws IOException
	 * @throws ParseException
	 */
	public static JSONObject search(String query, Integer nPages, Integer nResults, Integer offset) throws IOException, ParseException{
		String params = "q="+query;
		if(nPages!=null){
			params.concat("&p="+nPages);
		}
		if(nResults!=null){
			params.concat("&l="+nResults);
		}
		if(offset!=null){
			params.concat("&o="+offset);
		}
		return request("info", params);
	}
	/**
	 * Download a metasploit module given the fullname (id) of it.
	 * @param id : fullname of the module (ex. auxiliary/admin/backupexec/dump)
	 * @return : A dictionary with the following fields:
            filename        -- Name of the file
            content-type    -- Mimetype
            data            -- File content
	 * @throws IOException
	 * @throws ParseException
	 */
	public static JSONObject MSFDownload(String id) throws IOException, ParseException{
		return request("msf/download", "id="+id); 
	}
	/**
	 * Search for a Metasploit module.
	 * @param query
	 * @return
	 * @throws IOException
	 * @throws ParseException
	 */
	public static JSONObject MSFSearch(String query) throws IOException, ParseException{
		return request("msf/search", "q="+query); 
	}
	/**
	 * Download the exploit code from the ExploitDB archive.
	 * @param id : ID of the ExploitDB entry
	 * @return A dictionary with the following fields:
            filename        -- Name of the file
            content-type    -- Mimetype
            data            -- Contents of the file
	 * @throws IOException
	 * @throws ParseException
	 */
	public static JSONObject ExploitDBDownload(String id) throws IOException, ParseException{
		return request("exploitdb/download", "id="+id); 
	}
	/**
	 * Search the ExploitDB archive.
	 * @param query
	 * @param author
	 * @param platform
	 * @param port
	 * @param type
	 * @return A dictionary with 2 main items: matches (list) and total (int).
            Each item in 'matches' is a dictionary with the following elements:
            id
            author
            date
            description
            platform
            port
            type
	 * @throws IOException
	 * @throws ParseException
	 */
	public static JSONObject ExploitDBSearch(String query, String author, String platform, String port, String type) throws IOException, ParseException{
		String params = "q="+query;
				
		if(author!=null){
			params.concat("&author="+author);
		}
		if(platform!=null){
			params.concat("&platform="+platform);
		}
		if(port!=null){
			params.concat("&port="+port);
		}
		if(type!=null){
			params.concat("&type="+type);
		}
	
		return request("exploitdb/search", params); 
	}
	/**
	 * Search the entire Shodan Exploits archive using the same query syntax
            as the website.
	 * @param query : exploit search query; same syntax as website
	 * @param cve : metasploit, cve, osvdb, exploitdb, or packetstorm
	 * @param osvdb
	 * @param msb
	 * @param bid
	 * @return
	 * @throws IOException
	 * @throws ParseException
	 */
	public static JSONObject ExploitsSearch(String query, String cve, String osvdb, String msb, String bid) throws IOException, ParseException{
		String params = "q="+query;
		
		if(cve!=null){
			params.concat("&cve="+cve);
		}
		if(osvdb!=null){
			params.concat("&osvdb="+osvdb);
		}
		if(msb!=null){
			params.concat("&msb="+msb);
		}
		if(bid!=null){
			params.concat("&bid="+bid);
		}
		return request("search_exploits", params); 
	}
	
}
