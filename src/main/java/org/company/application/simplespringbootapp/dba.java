package org.company.application.simplespringbootapp;

import java.sql.PreparedStatement;
import java.sql.Connection;
import java.sql.ResultSet;



public class dba {
	private Connection connect = null;
	
	public String db_lookup ( String str ) {
		// some kind of lookup
		// The value is bound as a parameter, never concatenated into the SQL text.
		String squery = "select * from somewhere where something = ?";
		try ( PreparedStatement pstmt = connect.prepareStatement( squery ) ) {
			pstmt.setString( 1, str );
			try ( ResultSet rs = pstmt.executeQuery() ) {
				if ( rs.next() ) {
					return rs.getString( 1 );
				}
				return null;
			}
		} catch ( Exception e ) {
			return null;
		}
	}
	
	public void init( Connection conn, String password ) {
		if ( password.equals("password") ) {
			connect = conn;
		}
	}
}

