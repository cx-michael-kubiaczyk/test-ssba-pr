package org.company.application.simplespringbootapp;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Tests for dba.db_lookup to verify SQL injection vulnerability is fixed.
 *
 * The fix replaces Statement + string concatenation with PreparedStatement
 * parameterized queries. These tests verify:
 *  1. Normal lookups execute via PreparedStatement (not raw Statement).
 *  2. SQL injection payloads are treated as literal data, not SQL syntax.
 *  3. A null result is returned gracefully when no rows match.
 */
public class dbaTest {

    private dba dbInstance;
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private ResultSet mockResultSet;

    @Before
    public void setUp() throws Exception {
        mockConnection = mock(Connection.class);
        mockPreparedStatement = mock(PreparedStatement.class);
        mockResultSet = mock(ResultSet.class);

        // Wire the mock: prepareStatement returns our mock PreparedStatement
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);

        dbInstance = new dba();
        // Inject the mocked connection via reflection (field: connect)
        java.lang.reflect.Field connectField = dba.class.getDeclaredField("connect");
        connectField.setAccessible(true);
        connectField.set(dbInstance, mockConnection);
    }

    /**
     * Verify that db_lookup uses PreparedStatement.prepareStatement() with a
     * parameterised SQL template (containing '?'), not Statement.createStatement().
     * This is the core SAST-recognized fix for CWE-89.
     */
    @Test
    public void testDbLookupUsesPreparedStatement() throws Exception {
        when(mockResultSet.next()).thenReturn(false);

        dbInstance.db_lookup("test@example.com");

        // Must call prepareStatement with a query containing '?' placeholder
        verify(mockConnection).prepareStatement(contains("?"));
        // Must NOT call createStatement() — that path led to SQL injection
        verify(mockConnection, never()).createStatement();
    }

    /**
     * Verify that the user-supplied email is bound as a parameter (setString),
     * never concatenated directly into the SQL string.
     */
    @Test
    public void testEmailBoundAsParameterNotConcatenated() throws Exception {
        when(mockResultSet.next()).thenReturn(false);
        String email = "user@domain.com";

        dbInstance.db_lookup(email);

        // The value must be bound at parameter index 1
        verify(mockPreparedStatement).setString(1, email);
    }

    /**
     * Classic SQL injection payload: ' OR '1'='1
     * Must be bound as literal data, not alter the query structure.
     * The PreparedStatement must still be prepared with the safe template.
     */
    @Test
    public void testSqlInjectionPayloadTreatedAsLiteralData() throws Exception {
        when(mockResultSet.next()).thenReturn(false);
        String maliciousInput = "' OR '1'='1";

        dbInstance.db_lookup(maliciousInput);

        // Query template must not contain the raw payload — it must use '?'
        verify(mockConnection).prepareStatement(contains("?"));
        // The payload is passed to setString as a literal value
        verify(mockPreparedStatement).setString(1, maliciousInput);
        // executeQuery() on the PreparedStatement is called (no string arg)
        verify(mockPreparedStatement).executeQuery();
    }

    /**
     * DROP TABLE injection payload; must be handled as data, not executed.
     */
    @Test
    public void testDropTablePayloadTreatedAsLiteralData() throws Exception {
        when(mockResultSet.next()).thenReturn(false);
        String maliciousInput = "'; DROP TABLE somewhere; --";

        dbInstance.db_lookup(maliciousInput);

        verify(mockConnection).prepareStatement(contains("?"));
        verify(mockPreparedStatement).setString(1, maliciousInput);
        verify(mockPreparedStatement).executeQuery();
    }

    /**
     * Union-based injection payload; must be handled as data.
     */
    @Test
    public void testUnionBasedInjectionPayloadTreatedAsLiteralData() throws Exception {
        when(mockResultSet.next()).thenReturn(false);
        String maliciousInput = "x' UNION SELECT password FROM users --";

        dbInstance.db_lookup(maliciousInput);

        verify(mockConnection).prepareStatement(contains("?"));
        verify(mockPreparedStatement).setString(1, maliciousInput);
        verify(mockPreparedStatement).executeQuery();
    }

    /**
     * Verify that when a result row exists, the first column is returned.
     */
    @Test
    public void testReturnsFirstColumnWhenRowFound() throws Exception {
        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getString(1)).thenReturn("found_value");

        String result = dbInstance.db_lookup("test@example.com");

        assertEquals("found_value", result);
    }

    /**
     * Verify that null is returned when no rows match (not an exception).
     */
    @Test
    public void testReturnsNullWhenNoRowFound() throws Exception {
        when(mockResultSet.next()).thenReturn(false);

        String result = dbInstance.db_lookup("nonexistent@example.com");

        assertNull(result);
    }

    /**
     * Verify that a SQLException from the database is handled gracefully
     * (returns null rather than propagating the exception).
     */
    @Test
    public void testHandlesSqlExceptionGracefully() throws Exception {
        when(mockPreparedStatement.executeQuery()).thenThrow(new SQLException("DB error"));

        String result = dbInstance.db_lookup("test@example.com");

        assertNull(result);
    }

    /**
     * Verify that the SQL template does NOT contain user input directly.
     * The prepared query string passed to prepareStatement must be a static
     * constant — it must not contain the value of the email parameter.
     */
    @Test
    public void testSqlTemplateDoesNotContainUserInput() throws Exception {
        when(mockResultSet.next()).thenReturn(false);
        String email = "injected_marker_value@test.com";

        dbInstance.db_lookup(email);

        // Capture the SQL string passed to prepareStatement
        org.mockito.ArgumentCaptor<String> sqlCaptor =
                org.mockito.ArgumentCaptor.forClass(String.class);
        verify(mockConnection).prepareStatement(sqlCaptor.capture());
        String capturedSql = sqlCaptor.getValue();

        // The email value must NOT appear literally in the SQL template
        assertFalse(
            "SQL template must not contain user input directly",
            capturedSql.contains(email)
        );
        // The template must use a '?' placeholder instead
        assertTrue(
            "SQL template must use '?' placeholder for parameterized binding",
            capturedSql.contains("?")
        );
    }
}
