package org.company.application.simplespringbootapp;

import java.sql.PreparedStatement;
import java.sql.Connection;
import java.sql.ResultSet;



public class dba {
	private Connection connect = null;

	public String db_lookup ( String str ) {
		// Use a PreparedStatement with a parameter placeholder to prevent SQL injection.
		// The user-supplied value is bound via setString(), keeping data separate from SQL code.
		try {
			String squery = "select * from somewhere where something=?";

			PreparedStatement pstmt = connect.prepareStatement( squery );
			pstmt.setString( 1, str );
			ResultSet rs = pstmt.executeQuery();

			if ( rs.next() ) {
				return rs.getString( 1 );
			}
			return null;
		} catch ( Exception e ) { return null; }
	}
	
	public void init( Connection conn, String password ) {
		if ( password.equals("password") ) {
			connect = conn;
		}
	}
}

