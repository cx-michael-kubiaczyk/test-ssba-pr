package org.company.application.simplespringbootapp;

import org.company.security.obsolete.sanitizers;
import org.springframework.web.util.HtmlUtils;
// another small change
public class ReportGenerator {
	private dba db = null;

	public static String showUserReport( String email ) {
		// HTML-encode the data retrieved from the database before embedding it in
		// the HTML response to prevent Stored XSS (CWE-79).
		String response = "The user's data: " + HtmlUtils.htmlEscape( user_lookup( email ) );
		return response;
	}
	
	public String user_lookup ( String email ) {
		// some kind of lookup
		String c_email = sanitizers.sanitize( email );
		
		String response = db.db_lookup( c_email );
		if ( response == null ) {
			response = "No results for " + email;
		}
		return response;
	}
	
	public void init( dba the_db ) {
		db = the_db;
	}
}
