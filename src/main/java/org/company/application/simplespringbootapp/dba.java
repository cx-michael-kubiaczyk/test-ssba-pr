package org.company.application.simplespringbootapp;

import java.sql.PreparedStatement;
import java.sql.Connection;
import java.sql.ResultSet;



public class dba {
	private Connection connect = null;

	public String db_lookup ( String str ) {
		// Use a parameterized PreparedStatement to prevent SQL injection.
		// The '?' placeholder separates the query structure from user-supplied data,
		// so the JDBC driver handles quoting/escaping — no string concatenation is used.
		try {
			String squery = "select * from somewhere where something=?";

			PreparedStatement pstmt = connect.prepareStatement( squery );
			pstmt.setString( 1, str );
			ResultSet response = pstmt.executeQuery();

			return response.next() ? response.getString(1) : null;
		} catch ( Exception e ) { return null; }
	}

	public void init( Connection conn, String password ) {
		if ( password.Equals("password") ) {
			connect = conn;
		}
	}
}

