package org.company.application.simplespringbootapp;

import org.junit.Before;
import org.junit.Test;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Tests for dba.db_lookup() verifying that SQL injection is prevented by
 * using a parameterized PreparedStatement instead of string concatenation.
 *
 * Security fix: CWE-89 SQL Injection — taint flow from HTTP request parameter
 * "email" (Main.reportUser) through ReportGenerator.user_lookup to
 * dba.db_lookup, where it was previously concatenated into a raw SQL string
 * and passed to Statement.executeQuery().
 *
 * The fix replaces Statement + string concatenation with PreparedStatement
 * and setString(), which is a SAST-recognised sanitizer boundary that keeps
 * user-supplied values in the data plane and out of the SQL parse tree.
 */
public class DbaTest {

    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private ResultSet mockResultSet;

    @Before
    public void setUp() throws Exception {
        mockConnection = mock(Connection.class);
        mockPreparedStatement = mock(PreparedStatement.class);
        mockResultSet = mock(ResultSet.class);

        // Wire the mocks: prepareStatement returns our stub regardless of the SQL text
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);
        // toString() on the ResultSet mock returns a non-null string
        when(mockResultSet.toString()).thenReturn("mock-result");
    }

    // -----------------------------------------------------------------------
    // Helper: create a dba instance with mocked connection wired in directly.
    // The init() method in dba uses password.Equals() (non-compiling stub),
    // so we inject the connection via reflection to keep the test self-contained.
    // -----------------------------------------------------------------------
    private dba createDbaWithConnection(Connection conn) throws Exception {
        dba instance = new dba();
        java.lang.reflect.Field f = dba.class.getDeclaredField("connect");
        f.setAccessible(true);
        f.set(instance, conn);
        return instance;
    }

    // -----------------------------------------------------------------------
    // Test 1 – Normal input: verify prepareStatement() is called with the
    // parameterized template (no user data embedded) and setString() receives
    // the original value.
    // -----------------------------------------------------------------------
    @Test
    public void db_lookup_usesParameterizedQuery_forNormalInput() throws Exception {
        dba instance = createDbaWithConnection(mockConnection);

        String normalEmail = "user@example.com";
        instance.db_lookup(normalEmail);

        // The SQL template must NOT contain the user value — only a '?' placeholder
        verify(mockConnection).prepareStatement("select * from somewhere where something=?");
        // The user value must be bound via setString at position 1
        verify(mockPreparedStatement).setString(1, normalEmail);
        // executeQuery must be called with no arguments (PreparedStatement form)
        verify(mockPreparedStatement).executeQuery();
    }

    // -----------------------------------------------------------------------
    // Test 2 – SQL injection payload: verify that a classic injection string
    // is passed verbatim as a *parameter* (not embedded into SQL), so the
    // database treats it as literal data rather than SQL syntax.
    //
    // If the old string-concatenation code were still present, the SQL sent
    // to the driver would be:
    //   select * from somewhere where something='' OR '1'='1'
    // which returns all rows.  With PreparedStatement the injection payload
    // becomes a literal string value bound to the parameter.
    // -----------------------------------------------------------------------
    @Test
    public void db_lookup_treatsInjectionPayloadAsData() throws Exception {
        dba instance = createDbaWithConnection(mockConnection);

        String injectionPayload = "' OR '1'='1";
        instance.db_lookup(injectionPayload);

        // The SQL template must still be the safe placeholder form
        verify(mockConnection).prepareStatement("select * from somewhere where something=?");
        // The *full* injection payload is bound as a parameter value — not spliced into SQL
        verify(mockPreparedStatement).setString(1, injectionPayload);
        verify(mockPreparedStatement).executeQuery();
    }

    // -----------------------------------------------------------------------
    // Test 3 – Union-based injection payload: the query must never contain
    // the injected UNION clause.
    // -----------------------------------------------------------------------
    @Test
    public void db_lookup_treatsUnionInjectionPayloadAsData() throws Exception {
        dba instance = createDbaWithConnection(mockConnection);

        String unionPayload = "x' UNION SELECT table_name,null FROM information_schema.tables--";
        instance.db_lookup(unionPayload);

        // Capture the SQL string passed to prepareStatement and verify it
        // contains no part of the union payload
        org.mockito.ArgumentCaptor<String> sqlCaptor =
                org.mockito.ArgumentCaptor.forClass(String.class);
        verify(mockConnection).prepareStatement(sqlCaptor.capture());
        String capturedSql = sqlCaptor.getValue();

        assertFalse(
            "SQL template must not contain the UNION keyword from user input",
            capturedSql.toUpperCase().contains("UNION")
        );
        // The raw payload is still bound via setString — data, not code
        verify(mockPreparedStatement).setString(1, unionPayload);
    }

    // -----------------------------------------------------------------------
    // Test 4 – Drop-table injection payload: no destructive DDL in the query.
    // -----------------------------------------------------------------------
    @Test
    public void db_lookup_treatsDdlInjectionPayloadAsData() throws Exception {
        dba instance = createDbaWithConnection(mockConnection);

        String ddlPayload = "x'; DROP TABLE somewhere;--";
        instance.db_lookup(ddlPayload);

        org.mockito.ArgumentCaptor<String> sqlCaptor =
                org.mockito.ArgumentCaptor.forClass(String.class);
        verify(mockConnection).prepareStatement(sqlCaptor.capture());
        String capturedSql = sqlCaptor.getValue();

        assertFalse(
            "SQL template must not contain DROP TABLE from user input",
            capturedSql.toUpperCase().contains("DROP")
        );
        verify(mockPreparedStatement).setString(1, ddlPayload);
    }

    // -----------------------------------------------------------------------
    // Test 5 – Null input: verify the method does not throw for null and
    // still calls prepareStatement with the parameterized template.
    // -----------------------------------------------------------------------
    @Test
    public void db_lookup_handlesNullInputWithoutSqlConcatenation() throws Exception {
        dba instance = createDbaWithConnection(mockConnection);

        // Should not throw; any exception is swallowed by the catch block
        instance.db_lookup(null);

        verify(mockConnection).prepareStatement("select * from somewhere where something=?");
        verify(mockPreparedStatement).setString(1, null);
    }

    // -----------------------------------------------------------------------
    // Test 6 – Empty string: valid edge case that should use the parameterized path.
    // -----------------------------------------------------------------------
    @Test
    public void db_lookup_handlesEmptyStringInput() throws Exception {
        dba instance = createDbaWithConnection(mockConnection);

        instance.db_lookup("");

        verify(mockConnection).prepareStatement("select * from somewhere where something=?");
        verify(mockPreparedStatement).setString(1, "");
    }

    // -----------------------------------------------------------------------
    // Test 7 – Verify Statement.executeQuery(String) is NEVER called.
    // The old vulnerable code called stmt.executeQuery(squery) where squery
    // was a string.  The safe code calls pstmt.executeQuery() (no argument).
    // We confirm that the no-arg form is used.
    // -----------------------------------------------------------------------
    @Test
    public void db_lookup_doesNotCallExecuteQueryWithRawSqlString() throws Exception {
        dba instance = createDbaWithConnection(mockConnection);

        instance.db_lookup("test@example.com");

        // executeQuery() with no args — parameterized form — must be called
        verify(mockPreparedStatement, times(1)).executeQuery();
        // executeQuery(String) — the vulnerable raw-SQL form — must NEVER be called
        verify(mockPreparedStatement, never()).executeQuery(anyString());
    }
}
