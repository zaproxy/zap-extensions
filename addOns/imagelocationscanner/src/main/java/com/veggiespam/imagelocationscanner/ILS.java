package com.veggiespam.imagelocationscanner;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;		// for debugging only
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

import com.drew.imaging.ImageMetadataReader;
import com.drew.imaging.ImageProcessingException;
import com.drew.metadata.Directory;
import com.drew.metadata.Metadata;
import com.drew.lang.GeoLocation;
import com.drew.metadata.TagDescriptor;
import com.drew.metadata.exif.GpsDirectory;
import com.drew.metadata.iptc.IptcDirectory;
import com.drew.metadata.iptc.IptcDescriptor;
import com.drew.metadata.exif.makernotes.PanasonicMakernoteDirectory;
import com.drew.metadata.exif.makernotes.PanasonicMakernoteDescriptor;
import com.drew.metadata.exif.makernotes.LeicaMakernoteDirectory;
import com.drew.metadata.exif.makernotes.LeicaMakernoteDescriptor;
import com.drew.metadata.exif.makernotes.ReconyxUltraFireMakernoteDirectory;
import com.drew.metadata.exif.makernotes.SamsungType2MakernoteDescriptor;
import com.drew.metadata.exif.makernotes.SamsungType2MakernoteDirectory;
import com.drew.metadata.exif.makernotes.ReconyxUltraFireMakernoteDescriptor;
import com.drew.metadata.exif.makernotes.ReconyxHyperFireMakernoteDirectory;
import com.drew.metadata.exif.makernotes.ReconyxHyperFireMakernoteDescriptor;
import com.drew.metadata.exif.makernotes.ReconyxHyperFire2MakernoteDirectory;
import com.drew.metadata.exif.makernotes.ReconyxHyperFire2MakernoteDescriptor;
import com.drew.metadata.exif.makernotes.CanonMakernoteDirectory;
import com.drew.metadata.exif.makernotes.CanonMakernoteDescriptor;
import com.drew.metadata.exif.makernotes.SigmaMakernoteDirectory;
import com.drew.metadata.exif.makernotes.SonyTag9050bDescriptor;
import com.drew.metadata.exif.makernotes.SonyTag9050bDirectory;
import com.drew.metadata.exif.makernotes.SigmaMakernoteDescriptor;
import com.drew.metadata.exif.makernotes.NikonType2MakernoteDirectory;
import com.drew.metadata.exif.makernotes.NikonType2MakernoteDescriptor;
import com.drew.metadata.exif.makernotes.OlympusMakernoteDirectory;
import com.drew.metadata.exif.makernotes.OlympusMakernoteDescriptor;
import com.drew.metadata.exif.makernotes.OlympusEquipmentMakernoteDirectory;
import com.drew.metadata.exif.makernotes.OlympusEquipmentMakernoteDescriptor;
import com.drew.metadata.exif.makernotes.FujifilmMakernoteDirectory;
import com.drew.metadata.exif.makernotes.FujifilmMakernoteDescriptor;

/**
 * Image Location and Privacy Scanner main static class.  Passively scans an
 * image data stream (jpg/png/etc) and reports if the image contains embedded
 * location or privacy information, such as Exif GPS, IPTC codes, and some
 * proprietary camera codes which may contain things like serial numbers.  This
 * class is designed to be a plug-in for both ZAP and Burp proxies.
 * 
 * @author  Jay Ball / github: veggiespam / twitter: @veggiespam / www.veggiespam.com
 * @license Apache License 2.0
 * @version 1.2
 * @see https://www.veggiespam.com/ils/
 */
public class ILS {

	/** A bunch of static strings that are used by both ZAP and Burp plug-ins. */
	public static final String pluginName = "Image Location and Privacy Scanner";

	public static final String pluginVersion = "1.2";
	public static final String alertTitle = "Image Exposes Location or Privacy Data";
	public static final String alertDetailPrefix = "This image embeds a location or leaks privacy-related data: ";
	public static final String alertBackground 
		= "The image was found to contain embedded location information, such as GPS coordinates, or "
		+ "another privacy exposure, such as camera serial number.  "
		+ "Depending on the context of the image in the website, "
		+ "this information may expose private details of the users of a site.  For example, a site that allows "
		+ "users to upload profile pictures taken in the home may expose the home's address.  ";
	public static final String remediationBackground 
		= "Before allowing images to be stored on the server and/or transmitted to the browser, strip out the "
		+ "embedded location information from image.  This could mean removing all Exif data or just the GPS "
		+ "component.  Other data, like serial numbers, should also be removed.";
	public static final String remediationDetail = null;
	public static final String referenceURL = "https://www.veggiespam.com/ils/"; 
	public static final String pluginAuthor = "Jay Ball (@veggiespam) www.veggiespam.com"; 

	private static final String EmptyString = "";
	private static final String TextSubtypeEnd = ": "; // colon space for plain text results

	private static final String HTML_subtype_begin = "<li>";
	private static final String HTML_subtype_title_end = "\n\t<ul>\n";
	private static final String HTML_subtype_end = "\t</ul></li>\n";

	private static final String HTML_finding_begin = "\t<li>";
	private static final String HTML_finding_end = "</li>\n";

	// Used in the results array and elsewhere, values are an index.
	public enum OutputFormat { 
		out_text,				// == 0
		out_html, 				// == 1
		out_md  				// == 2
	};

	public ILS() {
		// blank constructor
		super();
	}

	public String getAuthor() {
		return pluginAuthor;
	}

	/** Tests a data blob for Location or GPS information and returns the image location
	 * information as a string.  If no location is present or there is an error,
	 * the function will return an empty string of "".
	 * 
	 * @param data is a byte array that is an image file to test, such as entire jpeg file.
	 * @return String Array containing the Location data or an empty String indicating no GPS data found.
	 */
	public static String[] scanForLocationInImageBoth(byte[] data)   {
		String[] results = { EmptyString, EmptyString, EmptyString };
		
		// Extreme debugging code for making sure data from Burp/ZAP/new-proxy gets into 
		// ILS.  This code is very slow and not to be compiled in, even with if(debug)
		// types of constructs.  This code this will save the image file to disk for binary
		// import debugging.
		/*
		if (false) {
			String t[] = { EmptyString, EmptyString, EmptyString };
			try{
				TimeZone tz = TimeZone.getTimeZone("UTC");
				DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm'Z'"); // Quoted "Z" to indicate UTC, no timezone offset
				df.setTimeZone(tz);
				String nowAsISO = df.format(new Date());
				FileOutputStream o = new FileOutputStream(new File("/tmp/ILS-debug-" + nowAsISO + ".jpg"));
				o.write(data);
				o.close();
			} catch (IOException e) {
				t[0] = "IOException Exception " + e.toString();
				t[1] = t[0];
				t[2] = t[0];
				return t;
			}
			t[0] = "Scanning " + data.length + "\n\n";
			t[1] = t[0];
			t[2] = t[0];
			// return t;   
			//   --- if you use this return line, remember to comment out rest of function.
		}
		*/
		
		try {
			BufferedInputStream is = new BufferedInputStream(new ByteArrayInputStream(data, 0, data.length));
			Metadata md = ImageMetadataReader.readMetadata(is);

			String[] tmp = { EmptyString, EmptyString, EmptyString };

			tmp = scanForLocation(md);
			results = scanForPrivacy(md);

			if (tmp[0].length() > 0) {
				// minor formatting update if we have both Location and Privacy.
				results[0] = tmp[0] + "" + results[0];
				results[1] = "<ul>"  +  tmp[1] + results[1] + "</ul>";
				results[2] = "    "  +  tmp[2] + results[2];

				/*
				// AGAIN: this is for extreme debugging
				results[0] = "DBG: " + t[0] + "\n\n" + results[0];
				results[1] = "DBG: " + t[1] + "\n\n" + results[1]; 
				results[2] = "DBG: " + t[2] + "\n\n" + results[2]; 
				 */
			}


		} catch (ImageProcessingException e) {
			// bad image, just ignore processing exceptions
			// DEBUG: return new String("ImageProcessingException: " + e.toString());
		} catch (IOException e) {
			// bad file or something, just ignore 
			// DEBUG: return new String("IOException: " + e.toString());
		}

		return results; 
	}


	/** Returns ILS information as HTML formatting string.
	 * 
	 * @see scanForLocationInImageBoth
	 */
	public static String scanForLocationInImageHTML(byte[] data)   {
		return scanForLocationInImageBoth(data)[1];
	}

	/** Returns ILS information as Text formatting string.
	 * 
	 * @see scanForLocationInImageBoth
	 */
	public static String scanForLocationInImageText(byte[] data)   {
		return scanForLocationInImageBoth(data)[0];
	}

	/** Returns ILS information as Markdown formatting string.
	 * 
	 * @see scanForLocationInImageBoth
	 */
	public static String scanForLocationInImageMD(byte[] data)   {
		return scanForLocationInImageBoth(data)[2];
	}

	/** Returns ILS information in Text or HTML depending on usehtml flag.
	 * 
	 * @param data is a byte array that is an image file to test, such as entire jpeg file.
	 * @param usehtml output as html (true) or plain txt (false)
	 * @return String containing the Location data or an empty String indicating no GPS data found.
	 * @see scanForLocationInImageBoth
	 * @deprecated "Use scanForLocationInImage(byte[] data, OutputFormat outputtype) instead. - removal in ILS v2.0"
	 */
	@Deprecated
	public static String scanForLocationInImage(byte[] data, boolean usehtml)   {
		if (usehtml) {
			return scanForLocationInImageHTML(data);
		} else {
			return scanForLocationInImageText(data);
		}
	}

	/** Returns ILS information in Text or HTML or Markdown depending on outputtype flag.
	 * 
	 * @param data is a byte array that is an image file to test, such as entire jpeg file.
	 * @param outputtype output as html (true) or plain txt (false)
	 * @return String containing the Location data or an empty String indicating no GPS data found.
	 * @see scanForLocationInImageBoth
	 */
	public static String scanForLocationInImage(byte[] data, OutputFormat outputtype)   {
		switch (outputtype) {
			case out_text:
				return scanForLocationInImageText(data);
			case out_html:
				return scanForLocationInImageHTML(data);
			case out_md:
				return scanForLocationInImageMD(data);
			default:
				return scanForLocationInImageText(data);
		}
	}


	/** Appends a new finding to the finding output. 
	 *  @param current The current set of findings, text and HTML.
	 *  @param bigtype the major category of exposure type, be it "Privacy" or "Location"
	 *  @param subtype place where exposure lives in the file, such as Exif, IPTC, or proprietary camera Makernote, like "Panasonic".
	 *  @param exposure a list of of strings that describe the exposure; each string is considered a single point of exposure in that one file.
	 *  @return Two strings as an array, first string is formatted text, second is HTML.
	 */
	private static String[] appendResults(String current[], String bigtype, String subtype, ArrayList<String> exposure)   {
		String[] tmp = formatResults(bigtype, subtype, exposure);

		if (tmp[0].length() > 0) {
			current[0] = current[0] + tmp[0];
			current[1] = current[1] + tmp[1];
			current[2] = current[2] + tmp[2];
		}
		return current;
	}

	/** Do this for completeness, even if a no-op for now. */
	private static String escapeTEXT(String s) {
		return s;  // might want to do more here someday, like binary data as hex codes, etc...
	}

	/** Theoretical chance of XSS inside of Burp/ZAP, so return properly escaped HTML. */
	private static String escapeHTML(String s) {
		return s.replace("&","&amp;").replace("<","&gt;");
	}

	/** Since MD allows HTML directly, escape as HTML.  Probably needs more work. */
	private static String escapeMD(String s) {
		return escapeHTML(s);
	}

	/** Formats the findings in both text and HTML.  
	 *  @param bigtype the major category of exposure type, be it "Privacy" or "Location"
	 *  @param subtype place where exposure lives in the file, such as Exif, IPTC, or proprietary camera Makernote, like "Panasonic".
	 *  @param exposure a list of of strings that describe the exposure; each string is considered a single point of exposure in that one file.
	 *  @return Two strings as an array, first string is formatted text, second is HTML.
	 */
	private static String[] formatResults(String bigtype, String subtype, ArrayList<String> exposure)   {
		StringBuffer ret = new StringBuffer(200);
		StringBuffer retHTML = new StringBuffer(200);
		StringBuffer retMD = new StringBuffer(200);
		String[] retarr = { EmptyString, EmptyString, EmptyString };

		if (exposure.size() > 0) {
			retHTML.append(HTML_subtype_begin).append(bigtype).append(" / ").append(subtype).append(HTML_subtype_title_end);
			for (String finding : exposure) {
				ret.append("\n    ").append(subtype).append(TextSubtypeEnd).append(escapeTEXT(finding));
				retHTML.append(HTML_finding_begin).append(escapeHTML(finding)).append(HTML_finding_end);
				retMD.append("\n    * ").append(subtype).append(TextSubtypeEnd).append(escapeMD(finding));
			}
			retHTML.append(HTML_subtype_end);
		}

		retarr[0] = ret.toString();
		retarr[1] = retHTML.toString();
		retarr[2] = retMD.toString();

		return retarr;
	}




	public static String[] scanForLocation(Metadata md)   {
		ArrayList<String> exposure = new ArrayList<String>();

		String[] results = { EmptyString, EmptyString, EmptyString };

		String bigtype = "Location";  // Overall category type.  Location or Privacy
		String subtype = EmptyString;

		// ** Standard Exif GPS
		subtype = "Exif_GPS";
		Collection<GpsDirectory> gpsDirColl = md.getDirectoriesOfType(GpsDirectory.class);

		if (gpsDirColl != null) {
			exposure.clear();

			for (GpsDirectory gpsDir : gpsDirColl) {
				final GeoLocation geoLocation = gpsDir.getGeoLocation();
				if ( ! (geoLocation == null || geoLocation.isZero()) ) {
					String finding = geoLocation.toDMSString();

					exposure.add(finding);
				}

				String alt = gpsDir.getDescription(GpsDirectory.TAG_ALTITUDE);
				String altref = gpsDir.getDescription(GpsDirectory.TAG_ALTITUDE_REF);
				if (alt != null || altref != null) {
					String finding = "Altitude: " + (alt == null ? "unknown elevation" : alt) 
										    + " " + (altref == null ? EmptyString : altref);
					exposure.add(finding);
				}
			}
			results = appendResults(results, bigtype, subtype, exposure);
		}


		// ** IPTC testing
		subtype = "IPTC";
		Collection<IptcDirectory> iptcDirColl = md.getDirectoriesOfType(IptcDirectory.class);

		int iptc_tag_list[] = {
			IptcDirectory.TAG_CITY,
			IptcDirectory.TAG_SUB_LOCATION,
			IptcDirectory.TAG_PROVINCE_OR_STATE,
			IptcDirectory.TAG_CONTENT_LOCATION_CODE,
			IptcDirectory.TAG_CONTENT_LOCATION_NAME,
			IptcDirectory.TAG_COUNTRY_OR_PRIMARY_LOCATION_CODE,
			IptcDirectory.TAG_COUNTRY_OR_PRIMARY_LOCATION_NAME,
			IptcDirectory.TAG_DESTINATION,
		};

		if (iptcDirColl != null) {
			exposure.clear();

			for (IptcDirectory iptcDir : iptcDirColl) {
				IptcDescriptor iptcDesc = new IptcDescriptor(iptcDir);
				for (int i=0; i< iptc_tag_list.length; i++) {
					String tag = iptcDesc.getDescription(iptc_tag_list[i]);
					// Sometimes, a space is used in fields
					if ( ! ( null == tag || tag.equals(EmptyString) || tag.equals(" ") || tag.charAt(0) == '\0' )) {
						exposure.add( iptcDir.getTagName(iptc_tag_list[i]) + " = '" + tag +"'");
					}
				}
			}

			results = appendResults(results, bigtype, subtype, exposure);
		}


		// ** LOCATION: Proprietary camera: Panasonic / Lumix
		subtype = "Panasonic";
		Collection<PanasonicMakernoteDirectory> panasonicDirColl = md.getDirectoriesOfType(PanasonicMakernoteDirectory.class);

		int panasonic_tag_list[] = {
			PanasonicMakernoteDirectory.TAG_CITY,
			PanasonicMakernoteDirectory.TAG_COUNTRY,
			PanasonicMakernoteDirectory.TAG_LANDMARK,
			PanasonicMakernoteDirectory.TAG_LOCATION,
			PanasonicMakernoteDirectory.TAG_STATE,
			//PanasonicMakernoteDirectory.TAG_WORLD_TIME_LOCATION  // might expose timezone aka location - but I only see value "HOME" in my samples.
		};

		if (panasonicDirColl != null) {
			exposure.clear();

			for (PanasonicMakernoteDirectory panasonicDir : panasonicDirColl) {
				PanasonicMakernoteDescriptor descriptor = new PanasonicMakernoteDescriptor(panasonicDir);
				for (int i=0; i< panasonic_tag_list.length; i++) {
					String tag = descriptor.getDescription(panasonic_tag_list[i]);
					// Panasonic occasionally uses "---" when it cannot complete a field or "Off" when no data is present, we choose to ignore these fields.
					if ( ! ( null == tag || tag.equals(EmptyString) || tag.equals("---") || tag.equals("Off")|| tag.charAt(0) == '\0' )) {
						exposure.add(panasonicDir.getTagName(panasonic_tag_list[i]) + " = " + tag);
					}
				}
			}

			results = appendResults(results, bigtype, subtype, exposure);
		}


		// For Text, add the big type in the initial entry
		if (results[0].length() > 0) {
			results[0] = "\n  " + bigtype + ":: " + results[0];
		}

		// For MD, add the big type in the initial entry
		if (results[2].length() > 0) {
			results[2] = "\n* " + bigtype + ":: " + results[2];
		}

		return results;
	}

	public static String[] scanForPrivacy(Metadata md)   {
		String bigtype = "Privacy";  // Overall category type.
		String subtype = EmptyString;
		ArrayList<String> exposure = new ArrayList<String>();

		String[] results = { EmptyString, EmptyString, EmptyString };

		/*  See https://github.com/drewnoakes/metadata-extractor/commit/5b07a49f7b3d90c43a36a79dc4f6474845e1ebc7
			for the reasons why this was disabled.


		// ** XMP testing
		subtype = "XMP";
		Collection<XmpDirectory> xmpDirColl = md.getDirectoriesOfType(XmpDirectory.class);

		int xmp_tag_list[] = {
			XmpDirectory.TAG_CAMERA_SERIAL_NUMBER 
		};

		if (xmpDirColl != null) {
			exposure.clear();

			for (XmpDirectory xmpDir : xmpDirColl) {
				XmpDescriptor xmpDesc = new XmpDescriptor(xmpDir);
				for (int i=0; i< xmp_tag_list.length; i++) {
					String tag = xmpDesc.getDescription(xmp_tag_list[i]);
					if ( ! ( null == tag || tag.equals(EmptyString) || tag.charAt(0) == '\0' )) {
						exposure.add( xmpDir.getTagName(xmp_tag_list[i]) + " = " + tag );
					}
				}
				results = appendResults(results, bigtype, subtype, exposure);
			}
		}
		*/

		// ** IPTC testing
		subtype = "IPTC";
		Collection<IptcDirectory> iptcDirColl = md.getDirectoriesOfType(IptcDirectory.class);

		int iptc_tag_list[] = {
			IptcDirectory.TAG_KEYWORDS,
			IptcDirectory.TAG_LOCAL_CAPTION
			// what about CREDIT   BY_LINE  ...
		};

		if (iptcDirColl != null) {
			exposure.clear();

			for (IptcDirectory iptcDir : iptcDirColl) {
				IptcDescriptor iptcDesc = new IptcDescriptor(iptcDir);
				for (int i=0; i< iptc_tag_list.length; i++) {
					String tag = iptcDesc.getDescription(iptc_tag_list[i]);
					if ( ! ( null == tag || tag.equals(EmptyString) || tag.equals("---") || tag.equals("Off") || tag.equals(" ") || tag.charAt(0) == '\0' )) {
						exposure.add( iptcDir.getTagName(iptc_tag_list[i]) + " = " + tag );
					}
				}
			}

			results = appendResults(results, bigtype, subtype, exposure);
		}

		// ** Proprietary camera: Canon
		subtype = "Canon";
		Collection<CanonMakernoteDirectory> canonDirColl = md.getDirectoriesOfType(CanonMakernoteDirectory.class);

		int canon_tag_list[] = {
			CanonMakernoteDirectory.TAG_CANON_OWNER_NAME, 
			CanonMakernoteDirectory.TAG_CANON_SERIAL_NUMBER
		};

		if (canonDirColl != null) {
			exposure.clear();

			for (CanonMakernoteDirectory canonDir: canonDirColl) {
				CanonMakernoteDescriptor descriptor = new CanonMakernoteDescriptor(canonDir);
				for (int i=0; i< canon_tag_list.length; i++) {
					String tag = descriptor.getDescription(canon_tag_list[i]);
					if ( ! ( null == tag || tag.equals(EmptyString) || tag.equals("---") || tag.equals("Off") || tag.equals(" ") || tag.charAt(0) == '\0' )) {
						exposure.add(canonDir.getTagName(canon_tag_list[i]) + " = " + tag);
					}
				}
			}

			results = appendResults(results, bigtype, subtype, exposure);
		}

		// ** Proprietary camera: FujiFilm
		subtype = "FujiFilm";
		Collection<FujifilmMakernoteDirectory> fujifilmDirColl = md.getDirectoriesOfType(FujifilmMakernoteDirectory.class);

		int fujifilm_tag_list[] = {
			FujifilmMakernoteDirectory.TAG_SERIAL_NUMBER
		};

		if (fujifilmDirColl != null) {
			exposure.clear();

			for (FujifilmMakernoteDirectory fujifilmDir: fujifilmDirColl) {
				FujifilmMakernoteDescriptor descriptor = new FujifilmMakernoteDescriptor(fujifilmDir);
				for (int i=0; i< fujifilm_tag_list.length; i++) {
					String tag = descriptor.getDescription(fujifilm_tag_list[i]);
					if ( ! ( null == tag || tag.equals(EmptyString) || tag.equals("---") || tag.equals("Off") || tag.equals(" ") || tag.charAt(0) == '\0' )) {
						exposure.add(fujifilmDir.getTagName(fujifilm_tag_list[i]) + " = " + tag);
					}
				}
			}

			results = appendResults(results, bigtype, subtype, exposure);
		}

		// ** Proprietary camera: Leica
		subtype = "Leica";
		Collection<LeicaMakernoteDirectory> leicaDirColl = md.getDirectoriesOfType(LeicaMakernoteDirectory.class);

		int leica_tag_list[] = {
			LeicaMakernoteDirectory.TAG_SERIAL_NUMBER
		};

		if (leicaDirColl != null) {
			exposure.clear();

			for (LeicaMakernoteDirectory leicaDir : leicaDirColl) {
				LeicaMakernoteDescriptor descriptor = new LeicaMakernoteDescriptor(leicaDir);
				for (int i=0; i< leica_tag_list.length; i++) {
					String tag = descriptor.getDescription(leica_tag_list[i]);
					if ( ! ( null == tag || tag.equals(EmptyString) || tag.equals("---") || tag.equals("Off") || tag.equals(" ") || tag.charAt(0) == '\0' )) {
						exposure.add(leicaDir.getTagName(leica_tag_list[i]) + " = " + tag);
					}
				}
			}

			results = appendResults(results, bigtype, subtype, exposure);
		}

		// ** Proprietary camera: Nikon Type 2 (type 1 has no privacy leakage)
		subtype = "Nikon";
		Collection<NikonType2MakernoteDirectory> nikonDirColl = md.getDirectoriesOfType(NikonType2MakernoteDirectory.class);

		int nikon_tag_list[] = {
			NikonType2MakernoteDirectory.TAG_CAMERA_SERIAL_NUMBER,
			NikonType2MakernoteDirectory.TAG_CAMERA_SERIAL_NUMBER_2
		};

		if (nikonDirColl != null) {
			exposure.clear();

			for (NikonType2MakernoteDirectory nikonDir: nikonDirColl) {
				NikonType2MakernoteDescriptor descriptor = new NikonType2MakernoteDescriptor(nikonDir);
				for (int i=0; i< nikon_tag_list.length; i++) {
					String tag = descriptor.getDescription(nikon_tag_list[i]);
					if ( ! ( null == tag || tag.equals(EmptyString) || tag.equals("---") || tag.equals("Off") || tag.equals(" ") || tag.charAt(0) == '\0' )) {
						exposure.add(nikonDir.getTagName(nikon_tag_list[i]) + " = " + tag);
					}
				}
			}

			results = appendResults(results, bigtype, subtype, exposure);
		}

		// ** Proprietary camera: Olympus
		subtype = "Olympus";
		Collection<OlympusMakernoteDirectory> olympusDirColl = md.getDirectoriesOfType(OlympusMakernoteDirectory.class);

		int olympus_tag_list[] = {
			OlympusMakernoteDirectory.TAG_SERIAL_NUMBER_1,
			OlympusMakernoteDirectory.TAG_SERIAL_NUMBER_2
		};

		if (olympusDirColl != null) {
			exposure.clear();

			for (OlympusMakernoteDirectory olympusDir: olympusDirColl) {
				OlympusMakernoteDescriptor descriptor = new OlympusMakernoteDescriptor(olympusDir);
				for (int i=0; i< olympus_tag_list.length; i++) {
					String tag = descriptor.getDescription(olympus_tag_list[i]);
					if ( ! ( null == tag || tag.equals(EmptyString) || tag.equals("---") || tag.equals("Off") || tag.equals(" ") || tag.charAt(0) == '\0' )) {
						exposure.add(olympusDir.getTagName(olympus_tag_list[i]) + " = " + tag);
					}
				}
			}

			results = appendResults(results, bigtype, subtype, exposure);
		}

		// ** Proprietary camera: OlympusEquipment
		subtype = "OlympusEquipment";
		Collection<OlympusEquipmentMakernoteDirectory> olympusEquipmentDirColl = md.getDirectoriesOfType(OlympusEquipmentMakernoteDirectory.class);

		int olympusEquipment_tag_list[] = {
			OlympusEquipmentMakernoteDirectory.TAG_SERIAL_NUMBER,
			OlympusEquipmentMakernoteDirectory.TAG_INTERNAL_SERIAL_NUMBER,
			OlympusEquipmentMakernoteDirectory.TAG_LENS_SERIAL_NUMBER,
			OlympusEquipmentMakernoteDirectory.TAG_EXTENDER_SERIAL_NUMBER,
			OlympusEquipmentMakernoteDirectory.TAG_FLASH_SERIAL_NUMBER
		};

		if (olympusEquipmentDirColl != null) {
			exposure.clear();

			for (OlympusEquipmentMakernoteDirectory olympusEquipmentDir: olympusEquipmentDirColl) {
				OlympusEquipmentMakernoteDescriptor descriptor = new OlympusEquipmentMakernoteDescriptor(olympusEquipmentDir);
				for (int i=0; i< olympusEquipment_tag_list.length; i++) {
					String tag = descriptor.getDescription(olympusEquipment_tag_list[i]);
					if ( ! ( null == tag || tag.equals(EmptyString) || tag.equals("---") || tag.equals("Off") || tag.equals(" ") || tag.charAt(0) == '\0' )) {
						exposure.add(olympusEquipmentDir.getTagName(olympusEquipment_tag_list[i]) + " = " + tag);
					}
				}
			}

			results = appendResults(results, bigtype, subtype, exposure);
		}

				
		// ** Proprietary camera: Panasonic / Lumix
		subtype = "Panasonic";
		Collection<PanasonicMakernoteDirectory> panasonicDirColl = md.getDirectoriesOfType(PanasonicMakernoteDirectory.class);

		int panasonic_tag_list[] = {
			PanasonicMakernoteDirectory.TAG_BABY_AGE,
			PanasonicMakernoteDirectory.TAG_BABY_AGE_1,
			PanasonicMakernoteDirectory.TAG_BABY_NAME,
			PanasonicMakernoteDirectory.TAG_FACE_RECOGNITION_INFO,
			PanasonicMakernoteDirectory.TAG_INTERNAL_SERIAL_NUMBER,
			PanasonicMakernoteDirectory.TAG_LENS_SERIAL_NUMBER,
			PanasonicMakernoteDirectory.TAG_TEXT_STAMP,
			PanasonicMakernoteDirectory.TAG_TEXT_STAMP_1,
			PanasonicMakernoteDirectory.TAG_TEXT_STAMP_2,
			PanasonicMakernoteDirectory.TAG_TEXT_STAMP_3,
			PanasonicMakernoteDirectory.TAG_TITLE
			// remember, all Panasonic-proprietary location tags are in the GPS scanning function.
		};

		if (panasonicDirColl != null) {
			exposure.clear();

			for (PanasonicMakernoteDirectory panasonicDir : panasonicDirColl) {
				PanasonicMakernoteDescriptor descriptor = new PanasonicMakernoteDescriptor(panasonicDir);
				for (int i=0; i< panasonic_tag_list.length; i++) {
					String tag = descriptor.getDescription(panasonic_tag_list[i]);
					if ( ! ( null == tag || tag.equals(EmptyString) || tag.equals("---") || tag.equals("Off") || tag.equals(" ") || tag.charAt(0) == '\0' )) {
						exposure.add(panasonicDir.getTagName(panasonic_tag_list[i]) + " = " + tag);
					}
				}
			}

			results = appendResults(results, bigtype, subtype, exposure);
		}

		// ** Proprietary camera: ReconyxHyperFire2
		subtype = "ReconyxHyperFire2";
		Collection<ReconyxHyperFire2MakernoteDirectory> reconyxHyperFire2DirColl = md.getDirectoriesOfType(ReconyxHyperFire2MakernoteDirectory.class);

		int reconyxHyperFire2_tag_list[] = {
			ReconyxHyperFire2MakernoteDirectory.TAG_SERIAL_NUMBER,
			ReconyxHyperFire2MakernoteDirectory.TAG_USER_LABEL
		};

		if (reconyxHyperFire2DirColl != null) {
			exposure.clear();

			for (ReconyxHyperFire2MakernoteDirectory reconyxHyperFire2Dir : reconyxHyperFire2DirColl) {
				ReconyxHyperFire2MakernoteDescriptor descriptor = new ReconyxHyperFire2MakernoteDescriptor(reconyxHyperFire2Dir);
				for (int i=0; i< reconyxHyperFire2_tag_list.length; i++) {
					String tag = descriptor.getDescription(reconyxHyperFire2_tag_list[i]);
					if ( ! ( null == tag || tag.equals(EmptyString) || tag.equals("---") || tag.equals("Off") || tag.equals(" ") || tag.charAt(0) == '\0' )) {
						exposure.add(reconyxHyperFire2Dir.getTagName(reconyxHyperFire2_tag_list[i]) + " = " + tag);
					}
				}
			}

			results = appendResults(results, bigtype, subtype, exposure);
		}

		// ** Proprietary camera: ReconyxHyperFire
		subtype = "ReconyxHyperFire";
		Collection<ReconyxHyperFireMakernoteDirectory> reconyxHyperFireDirColl = md.getDirectoriesOfType(ReconyxHyperFireMakernoteDirectory.class);

		int reconyxHyperFire_tag_list[] = {
			ReconyxHyperFireMakernoteDirectory.TAG_SERIAL_NUMBER,
			ReconyxHyperFireMakernoteDirectory.TAG_USER_LABEL
		};

		if (reconyxHyperFireDirColl != null) {
			exposure.clear();

			for (ReconyxHyperFireMakernoteDirectory reconyxHyperFireDir : reconyxHyperFireDirColl) {
				ReconyxHyperFireMakernoteDescriptor descriptor = new ReconyxHyperFireMakernoteDescriptor(reconyxHyperFireDir);
				for (int i=0; i< reconyxHyperFire_tag_list.length; i++) {
					String tag = descriptor.getDescription(reconyxHyperFire_tag_list[i]);
					if ( ! ( null == tag || tag.equals(EmptyString) || tag.equals("---") || tag.equals("Off") || tag.equals(" ") || tag.charAt(0) == '\0' )) {
						exposure.add(reconyxHyperFireDir.getTagName(reconyxHyperFire_tag_list[i]) + " = " + tag);
					}
				}
			}

			results = appendResults(results, bigtype, subtype, exposure);
		}


		// ** Proprietary camera: ReconyxUltraFire
		subtype = "ReconyxUltraFire";
		Collection<ReconyxUltraFireMakernoteDirectory> reconyxUltraFireDirColl = md.getDirectoriesOfType(ReconyxUltraFireMakernoteDirectory.class);

		int reconyxUltraFire_tag_list[] = {
			ReconyxUltraFireMakernoteDirectory.TAG_SERIAL_NUMBER,
			ReconyxUltraFireMakernoteDirectory.TAG_USER_LABEL
		};

		if (reconyxUltraFireDirColl != null) {
			exposure.clear();

			for (ReconyxUltraFireMakernoteDirectory reconyxUltraFireDir : reconyxUltraFireDirColl) {
				ReconyxUltraFireMakernoteDescriptor descriptor = new ReconyxUltraFireMakernoteDescriptor(reconyxUltraFireDir);
				for (int i=0; i< reconyxUltraFire_tag_list.length; i++) {
					String tag = descriptor.getDescription(reconyxUltraFire_tag_list[i]);
					if ( ! ( null == tag || tag.equals(EmptyString) || tag.equals("---") || tag.equals("Off") || tag.equals(" ") || tag.charAt(0) == '\0' )) {
						exposure.add(reconyxUltraFireDir.getTagName(reconyxUltraFire_tag_list[i]) + " = " + tag);
					}
				}
			}

			results = appendResults(results, bigtype, subtype, exposure);
		}



	// ** Proprietary camera: Samsung (Type2)
	{
		subtype = "Samsung-Type2";
		Collection<SamsungType2MakernoteDirectory> dircoll = md.getDirectoriesOfType(SamsungType2MakernoteDirectory.class);			

		final int taglist[] = {
			SamsungType2MakernoteDirectory.TagSerialNumber,
			SamsungType2MakernoteDirectory.TagFaceName,
			SamsungType2MakernoteDirectory.TagInternalLensSerialNumber,
			SamsungType2MakernoteDirectory.TagEncryptionKey
		};

		if (dircoll != null) {
			exposure.clear();

			for (SamsungType2MakernoteDirectory dir: dircoll) {
				SamsungType2MakernoteDescriptor descriptor = new SamsungType2MakernoteDescriptor(dir);
				for (int i=0; i< taglist.length; i++) {
					String tag = descriptor.getDescription(taglist[i]);
					if ( ! ( null == tag || tag.equals(EmptyString) || tag.equals("---") || tag.equals("Off") || tag.equals(" ") || tag.charAt(0) == '\0' )) {
						exposure.add(dir.getTagName(taglist[i]) + " = " + tag);
					}
				}
			}

			results = appendResults(results, bigtype, subtype, exposure);
		}
	}





		// ** Proprietary camera: Sigma
		subtype = "Sigma";
		Collection<SigmaMakernoteDirectory> sigmaDirColl = md.getDirectoriesOfType(SigmaMakernoteDirectory.class);

		int sigma_tag_list[] = {
			SigmaMakernoteDirectory.TAG_SERIAL_NUMBER
		};

		if (sigmaDirColl != null) {
			exposure.clear();

			for (SigmaMakernoteDirectory sigmaDir: sigmaDirColl) {
				SigmaMakernoteDescriptor descriptor = new SigmaMakernoteDescriptor(sigmaDir);
				for (int i=0; i< sigma_tag_list.length; i++) {
					String tag = descriptor.getDescription(sigma_tag_list[i]);
					if ( ! ( null == tag || tag.equals(EmptyString) || tag.equals("---") || tag.equals("Off") || tag.equals(" ") || tag.charAt(0) == '\0' )) {
						exposure.add(sigmaDir.getTagName(sigma_tag_list[i]) + " = " + tag);
					}
				}
			}

			results = appendResults(results, bigtype, subtype, exposure);
		}





		
		// ** Proprietary camera: Sony Tag 9050b
		{
			subtype = "Sony-Tag9050b";
			Collection<SonyTag9050bDirectory> dircoll = md.getDirectoriesOfType(SonyTag9050bDirectory.class);			

			final int taglist[] = {
				SonyTag9050bDirectory.TAG_INTERNAL_SERIAL_NUMBER
			};

			if (dircoll != null) {
				exposure.clear();

				for (SonyTag9050bDirectory dir: dircoll) {
					SonyTag9050bDescriptor descriptor = new SonyTag9050bDescriptor(dir);
					for (int i=0; i< taglist.length; i++) {
						String tag = descriptor.getDescription(taglist[i]);
						if ( ! ( null == tag || tag.equals(EmptyString) || tag.equals("---") || tag.equals("Off") || tag.equals(" ") || tag.charAt(0) == '\0' )) {
							exposure.add(dir.getTagName(taglist[i]) + " = " + tag);
						}
					}
				}

				results = appendResults(results, bigtype, subtype, exposure);
			}
		}




/*		
		List<Class<?>> dirs = List.of(FujifilmMakernoteDirectory.class);
		List<Class<?>> descriptorslist = List.of(FujifilmMakernoteDescriptor.class);
		List<String> subtypes= List.of("Fujifilm");
		List<int[]> taglists = List.of(
			new int[] { FujifilmMakernoteDirectory.TAG_SERIAL_NUMBER }
		);
		for (int i=0; i<dirs.size(); i++) {
			subtype = subtypes.get(i);
			int[] taglist = taglists.get(i);
			Class<?> dirClass = dirs.get(i);
			TagDescriptor descriptor = (TagDescriptor) descriptorslist.get(i).getConstructor(Directory.class).newInstance();
			@SuppressWarnings("unchecked")
			Collection<Directory> dirColl = (Collection<Directory>) md.getDirectoriesOfType((Class<Directory>) dirClass);

			if (dirColl != null) {
				exposure.clear();

				for (Directory d : dirColl) {
					for (int j=0; j< taglist.length; j++) {
						String tag = descriptor.getDescription(taglist[j]);
						if ( ! ( null == tag || tag.equals(EmptyString) || tag.charAt(0) == '\0' )) {
							exposure.add(d.getTagName(taglist[j]) + " = " + tag);
						}
					}
				}
				results = appendResults(results, bigtype, subtype, exposure);
			}
		}

		*/


		/* 
		for (Class<?> dir : dirs) {
			@SuppressWarnings("unchecked")
			Collection<Directory> dirColl = md.getDirectoriesOfType((Class<Directory>) dir);
			if (dirColl != null) {
				exposure.clear();

				for (Directory d : dirColl) {
					String tag = d.getDescription(0);
					if ( ! ( null == tag || tag.equals(EmptyString) || tag.charAt(0) == '\0' )) {
						exposure.add(d.getTagName(0) + " = " + tag);
					}
				}
				results = appendResults(results, bigtype, subtype, exposure);
			}
		}
		*/

		// For Text, add the big type in the initial entry
		if (results[0].length() > 0) {
			results[0] = "\n  " + bigtype + ":: " + results[0];
		}
		// For MD, add the big type in the initial entry
		if (results[2].length() > 0) {
			results[2] = "\n* " + bigtype + ":: " + results[2];
		}
		return results;
	}

	// Each paragraph is an array entry
	public static final String CommandLineHelp[] = {
		"Copyright © Jay Ball (@veggiespam)"
		,
		"See github.com/veggiespam/ImageLocationScanner - license Apache 2.0"
		,
		"Passively scans for GPS location and other privacy-related exposures in images during normal security  assessments of websites; this jar is also a plug-in for both Burp & ZAP.  Image Location and Privacy Scanner (ILS) assists in situations where end users may post profile images and possibly give away their home location, e.g. a dating site or children's chatroom."
		,
		"More information on this topic, including a white paper based on a real-world site audit given as a presentation at the New Jersey chapter of the OWASP organization, can be found at https://www.veggiespam.com/ils/"
		,
		"This software scans images to find the GPS information inside of Exif tags, IPTC codes, and proprietary camera tags. Then, it outputs the findings to the console " 
	};

	public static void main(String[] args) throws Exception {
		OutputFormat outputtype = OutputFormat.out_text;
		if (args.length == 0){
			System.out.println("Image Location and Privacy Scanner v" + pluginVersion);
			System.out.println("Usage: java ILS.class [-h|-m|-t] file1.jpg file2.png file3.txt [...]");
			System.out.println("    -h : output results in semi-HTML");
			System.out.println("    -m : output results in Markdown");
			System.out.println("    -t : output results in plain text (default)");
			System.out.println("    --help : detailed description");
			return;
		}

		for (String s: args) {
			if (s.equals("-t")) {
				outputtype = OutputFormat.out_text;
				continue;
			}			
			if (s.equals("-h")) {
				outputtype = OutputFormat.out_html;
				continue;
			}	
			if (s.equals("-m")) {
				outputtype = OutputFormat.out_md;
				continue;
			}
			if (s.equals("--help")) {
				System.out.println("Image Location and Privacy Scanner v" + pluginVersion);
				for (String para : CommandLineHelp) {
					// by vitaut from https://stackoverflow.com/questions/4212675/wrap-the-string-after-a-number-of-characters-word-wise-in-java
					// this code does not work on multi-paragraph \n'd string, thus added the array hack. 
					StringBuilder sb = new StringBuilder(para);
					int i = 0;
					int width = 80;
					while (i + width < sb.length() && (i = sb.lastIndexOf(" ", i + width)) != -1) {
						sb.replace(i, i + 1, "\n");
					}
					sb.append("\n");
					System.out.println(sb.toString());
				}
				System.exit(0);
			}



			File f = new File(s);
			try (FileInputStream fis = new FileInputStream(f)) {
				switch (outputtype) {
					case out_text:
						System.out.print("Processing " + s + " : ");
						break;
					case out_html:
						System.out.println("<h3>" + s + "</h3>");
						break;
					case out_md:
						System.out.print("# " + s);
						break;
				}

				long size = f.length();
				byte[] data = new byte[(int) size];
				long read = fis.read(data);
				if (read != size) {
				    System.out.println("There was a problem reading the file");
				}
				fis.close();
				
				String res = scanForLocationInImage(data, outputtype);
				if (0 == res.length())  {
					res = "None";
				}
				System.out.println(res);
			} catch (IOException e) {
				System.out.println(e.getMessage());
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
}

// vim: autoindent noexpandtab tabstop=4 shiftwidth=4
