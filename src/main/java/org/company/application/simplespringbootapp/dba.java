package org.company.application.simplespringbootapp;

import java.sql.Statement;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;



public class dba {
	private Connection connect = null;
	private Statement stmt = null;
	
	public String db_lookup ( String str ) {
		// some kind of lookup
		// Parameterized query: the value is bound as data, never parsed as SQL
		String squery = "select * from somewhere where something = ?";
		try ( PreparedStatement pstmt = connect.prepareStatement( squery ) ) {
			pstmt.setString( 1, str );
			try ( ResultSet rs = pstmt.executeQuery() ) {
				if ( rs.next() ) {
					return rs.getString( 1 );
				}
			}
		} catch ( Exception e ) { }
		return null;
	}
	
	public void init( Connection conn, String password ) {
		if ( password.equals("password") ) {
			connect = conn;
			try {
				stmt = conn.createStatement();
			} catch ( Exception e ) {

			}
		}
	}
}

