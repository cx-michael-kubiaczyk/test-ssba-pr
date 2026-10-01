package org.company.application.simplespringbootapp;

import java.sql.PreparedStatement;
import java.sql.Connection;



public class dba {
	private Connection connect = null;

	public String db_lookup ( String str ) {
		// Use a parameterized PreparedStatement to prevent SQL injection.
		// The '?' placeholder is bound via setString(), which ensures the
		// user-supplied value is treated as data, not as SQL syntax.
		try {
			String squery = "select * from somewhere where something=?";

			PreparedStatement pstmt = connect.prepareStatement( squery );
			pstmt.setString( 1, str );
			String response = pstmt.executeQuery().toString();

			return response;
		} catch ( Exception e ) { };
	}
	
	public void init( Connection conn, String password ) {
		if ( password.Equals("password") ) {
			connect = conn;
		}
	}
}

