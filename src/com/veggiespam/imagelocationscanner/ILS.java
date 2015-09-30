package com.veggiespam.imagelocationscanner;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;

import com.drew.imaging.ImageMetadataReader;
import com.drew.imaging.ImageProcessingException;
import com.drew.metadata.Metadata;
import com.drew.lang.GeoLocation;
import com.drew.metadata.exif.GpsDirectory;
import com.drew.metadata.iptc.IptcDirectory;
import com.drew.metadata.exif.makernotes.PanasonicMakernoteDirectory;

/**
 * Image Location Scanner main static class.  Passively scans an image data stream (jpg/png/etc)
 * and reports if the image contains embedded location information, such as Exif GPS, IPTC codes, and
 * some proprietary camera codes.  This class is designed to be a plug-in for both ZAP and Burp proxies.
 * 
 * @author  Jay Ball / github: veggiespam / twitter: @veggiespam / www.veggiespam.com
 * @license Apache License 2.0
 * @version 0.2
 * @see http://www.veggiespam.com/ils/
 */
public class ILS {

	/** A bunch of static strings that are used by both ZAP and Burp plug-ins. */
    public static final String pluginName = "Image Location Scanner";
    public static final String pluginVersion = "0.2";
    public static final String alertTitle = "Image Contains Embedded Location Information";
    public static final String alertDetailPrefix = "This image contains embedded location information: ";
    public static final String alertBackground 
    	= "The image was found to contain embedded location information, such as GPS coordinates.  "
    	+ "Depending on the context of the image in the website, "
    	+ "this information may expose private details of the users of a site.  For example, a site that allows "
    	+ "users to upload profile pictures taken in the home may expose the home's address.  ";
    public static final String remediationBackground 
    	= "Before allowing images to be stored on the server and/or transmitted to the browser, strip out the "
    	+ "embedded location information from image.  This could mean removing all Exif data or just the GPS "
    	+ "component.";
    public static final String remediationDetail = null;
    public static final String referenceURL = "http://www.veggiespam.com/ils/"; 
    public static final String pluginAuthor = "Jay Ball (veggiespam)"; 

	private static final String EmptyString = "";
	private static final String Space = " ";
	private static final String Seperator = " ||  ";  // one space at start, two at end


	public ILS() {
		// blank constructor
		super();
	}
	
    
	/** Tests a data blob for Location or GPS information and returns the image location
	 * information as a string.  If no location is present or there is an error,
	 * the function will return an empty string of "".
	 * 
	 * @param data is a byte array that is an image file to test, such as entire jpeg file.
	 * @return String containing the Location data or an empty String indicating no GPS data found.
	 */
    public static String scanForLocationInImage(byte[] data)   {
    	String ret = EmptyString;
		int findings = 0; // used for appending the separator if required, counts types of embbed locations
    	
    	/*  // Debugging code getting the data from Burp/ZAP/newproxy into ILS, ugh.
    	try{
       		FileOutputStream o = new FileOutputStream(new File("/tmp/output.jpg"));
			o.write(data);
			o.close();
    	} catch (IOException e) {
    		return new String("IOException Exception " + e.toString());
    	}
    	//return new String("Scanning " + data.length + "\n\n"  );
    	*/
 
    	try {
			BufferedInputStream is = new BufferedInputStream(new ByteArrayInputStream(data, 0, data.length));
			Metadata md = ImageMetadataReader.readMetadata(is);

			// ** Standard Exif GPS
			GpsDirectory gpsDir = md.getFirstDirectoryOfType(GpsDirectory.class);
			if (gpsDir != null) {
				String exifGPS = EmptyString;
				final GeoLocation geoLocation = gpsDir.getGeoLocation();
				if ( ! (geoLocation == null || geoLocation.isZero()) ) {
					exifGPS = "GPS: " + geoLocation.toDMSString() + Space;
					ret = exifGPS;
					findings++;
				}
			}


			// ** IPTC testing
			IptcDirectory iptcDir = md.getFirstDirectoryOfType(IptcDirectory.class);

			// These two arrays must be in same order & size or things will break
			int iptc_tag_list[] = {
				IptcDirectory.TAG_CONTENT_LOCATION_CODE,
				IptcDirectory.TAG_CONTENT_LOCATION_NAME,
				IptcDirectory.TAG_COUNTRY_OR_PRIMARY_LOCATION_CODE,
				IptcDirectory.TAG_COUNTRY_OR_PRIMARY_LOCATION_NAME,
				IptcDirectory.TAG_DESTINATION,
				IptcDirectory.TAG_KEYWORDS,
				IptcDirectory.TAG_LOCAL_CAPTION
			};
			String iptc_string_list[] = {
				"Content Location Code",
				"Content Location Name",
				"Country Code",
				"Country Name",
				"Destination",
				"Keywords",
				"Local Caption"
			};

			if (iptcDir != null) {
				String iptcRet = EmptyString;
				int p=0;
				for (int i=0; i< iptc_tag_list.length; i++) {
					String tag = iptcDir.getString(iptc_tag_list[i]);
					if (tag != null && ! tag.equals(EmptyString) ) {
						p++;
						iptcRet = iptcRet + iptc_string_list[i] + "=" + iptc_tag_list[i] + Space;
					}
				}
				if (p>0) {
					if (findings > 0) {
						ret = ret + Seperator;
					}
					ret = ret + "IPTC: " + iptcRet;
					findings++;
				}
			}



			// ** Proprietary camera: Panasonic / Lumix
			PanasonicMakernoteDirectory panasonicDir = md.getFirstDirectoryOfType(PanasonicMakernoteDirectory.class);

			// These two arrays must be in same order & size or things will break
			int panasonic_tag_list[] = {
				PanasonicMakernoteDirectory.TAG_CITY,
				PanasonicMakernoteDirectory.TAG_COUNTRY,
				PanasonicMakernoteDirectory.TAG_LANDMARK,
				PanasonicMakernoteDirectory.TAG_LOCATION,
				PanasonicMakernoteDirectory.TAG_STATE
			};
			String panasonic_string_list[] = {
                "City",
                "Country",
                "Landmark",
                "Location",
                "State"
			};

			if (panasonicDir != null) {
				String panRet = EmptyString;
				int p=0;
				for (int i=0; i< panasonic_tag_list.length; i++) {
					String tag = panasonicDir.getString(panasonic_tag_list[i]);
					if (tag != null && ! tag.equals(EmptyString) ) {
						p++;
						panRet = panRet + panasonic_string_list[i] + "=" + panasonic_tag_list[i] + Space;
					}
				}
				if (p>0) {
					if (findings > 0) {
						ret = ret + Seperator;
					}
					ret = ret + "Proprietary Panasonic/Lumix: " + panRet;
					findings++;
				}
			}

			/* We could do some metrics here.  The findings variable contains how many types
			   of locations are embedded: Exif, IPTC, Proprietary, etc.  Maybe a future concept. */


    	} catch (ImageProcessingException e) {
    		// bad image, just ignore processing exceptions
    		// DEBUG: return new String("ImageProcessingException " + e.toString());
    	} catch (IOException e) {
    		// bad file or something, just ignore 
    		// DEBUG: return new String("IOException " + e.toString());
    	}

    	return ret; 
    }


    
    public static void main(String[] args) throws Exception {
    	if (args.length == 0){
    		System.out.println("Java Image Location Scanner");
    		System.out.println("Usage: java ILS.class file1.jpg file2.png file3.txt [...]");
    		return;
    	}
    	for (String s: args) {
            try {
				System.out.print("Processing " + s + " : ");

				File f = new File(s);
				FileInputStream fis = new FileInputStream(f);
				long size = f.length();
				byte[] data = new byte[(int) size];
				fis.read(data);
				fis.close();
				
				String res = scanForLocationInImage(data);
				System.out.println(res);
        	} catch (IOException e) {
        		System.out.println(e.getMessage());
			} catch (Exception e) {
				e.printStackTrace();
			}
    	}
    }
}
