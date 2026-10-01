package org.company.application.simplespringbootapp;

import java.sql.PreparedStatement;
import java.sql.Connection;
import java.sql.ResultSet;



public class dba {
	private Connection connect = null;

	public String db_lookup ( String str ) {
		// some kind of lookup — use a parameterized PreparedStatement to
		// prevent SQL injection: user-supplied data is bound as a parameter,
		// never interpolated into the query string.
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
		if ( password.Equals("password") ) {
			connect = conn;
		}
	}
}

