package org.company.application.simplespringbootapp;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link dba#db_lookup(String)} to verify that the SQL injection
 * vulnerability (CWE-89) has been remediated via parameterized PreparedStatements.
 *
 * The fix replaces Statement + string concatenation with PreparedStatement,
 * so user-supplied values are always treated as data — never as SQL code.
 */
public class DbaTest {

    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private ResultSet mockResultSet;
    private dba database;

    @BeforeEach
    public void setUp() throws Exception {
        mockConnection = mock(Connection.class);
        mockPreparedStatement = mock(PreparedStatement.class);
        mockResultSet = mock(ResultSet.class);

        // Wire up the mock chain: connection → prepareStatement → executeQuery → ResultSet
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);

        database = new dba();
        database.init(mockConnection, "password");
    }

    // -----------------------------------------------------------------------
    // Parameterized-query structural tests
    // -----------------------------------------------------------------------

    /**
     * Verify that db_lookup calls prepareStatement (not createStatement).
     * This confirms a PreparedStatement is used, which is the SAST-recognized
     * pattern for preventing SQL injection.
     */
    @Test
    public void testDbLookupUsesPreparedStatement() throws Exception {
        when(mockResultSet.next()).thenReturn(false);

        database.db_lookup("test@example.com");

        // Must have called prepareStatement with a parameterised SQL string
        verify(mockConnection, times(1)).prepareStatement(anyString());
        // And must NOT have called createStatement (the unsafe path)
        verify(mockConnection, never()).createStatement();
    }

    /**
     * Verify that the SQL template uses a '?' placeholder (not string concatenation).
     */
    @Test
    public void testDbLookupUsesParameterPlaceholder() throws Exception {
        when(mockResultSet.next()).thenReturn(false);

        database.db_lookup("anyvalue");

        // Capture what was passed to prepareStatement
        verify(mockConnection).prepareStatement(argThat(sql ->
                sql.contains("?") && !sql.contains("'")
        ));
    }

    /**
     * Verify that the user-supplied value is bound via setString (parameterized),
     * not embedded into the SQL string itself.
     */
    @Test
    public void testDbLookupBindsParameterViaSetString() throws Exception {
        String emailInput = "user@example.com";
        when(mockResultSet.next()).thenReturn(false);

        database.db_lookup(emailInput);

        // The value must be bound to parameter index 1 — never concatenated into SQL
        verify(mockPreparedStatement, times(1)).setString(1, emailInput);
    }

    // -----------------------------------------------------------------------
    // SQL injection payload tests — confirm payloads are treated as data
    // -----------------------------------------------------------------------

    /**
     * Classic SQL injection: a single-quote payload that would break a
     * concatenated query must be passed verbatim to setString without altering
     * the SQL structure.
     */
    @Test
    public void testSqlInjectionSingleQuotePayloadBoundAsData() throws Exception {
        String injectionPayload = "' OR '1'='1";
        when(mockResultSet.next()).thenReturn(false);

        // Should not throw; the payload is treated as a literal string parameter
        String result = database.db_lookup(injectionPayload);

        // setString must have received the full, unmodified payload
        verify(mockPreparedStatement).setString(1, injectionPayload);
        // And the SQL template itself must not contain the payload
        verify(mockConnection).prepareStatement(argThat(sql -> !sql.contains(injectionPayload)));
    }

    /**
     * UNION-based injection payload must be bound as data.
     */
    @Test
    public void testSqlInjectionUnionPayloadBoundAsData() throws Exception {
        String injectionPayload = "' UNION SELECT password FROM users--";
        when(mockResultSet.next()).thenReturn(false);

        database.db_lookup(injectionPayload);

        verify(mockPreparedStatement).setString(1, injectionPayload);
        verify(mockConnection).prepareStatement(argThat(sql -> !sql.contains("UNION")));
    }

    /**
     * Boolean-based blind injection payload must be bound as data.
     */
    @Test
    public void testSqlInjectionBooleanPayloadBoundAsData() throws Exception {
        String injectionPayload = "1 OR 1=1";
        when(mockResultSet.next()).thenReturn(false);

        database.db_lookup(injectionPayload);

        verify(mockPreparedStatement).setString(1, injectionPayload);
    }

    /**
     * Stacked-query / semicolon injection payload must be bound as data.
     */
    @Test
    public void testSqlInjectionStackedQueryPayloadBoundAsData() throws Exception {
        String injectionPayload = "x'; DROP TABLE somewhere;--";
        when(mockResultSet.next()).thenReturn(false);

        database.db_lookup(injectionPayload);

        verify(mockPreparedStatement).setString(1, injectionPayload);
        // The SQL template sent to prepareStatement must never contain DROP
        verify(mockConnection).prepareStatement(argThat(sql -> !sql.contains("DROP")));
    }

    // -----------------------------------------------------------------------
    // Functional (positive) tests — normal usage must still work
    // -----------------------------------------------------------------------

    /**
     * A well-formed email address should return the value from the first column
     * of the ResultSet when a row is found.
     */
    @Test
    public void testDbLookupReturnsFirstColumnWhenRowExists() throws Exception {
        String email = "valid@example.com";
        String expectedValue = "some_result";

        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getString(1)).thenReturn(expectedValue);

        String result = database.db_lookup(email);

        assertEquals(expectedValue, result);
    }

    /**
     * When no row is found the method must return null (not throw).
     */
    @Test
    public void testDbLookupReturnsNullWhenNoRowFound() throws Exception {
        when(mockResultSet.next()).thenReturn(false);

        String result = database.db_lookup("notfound@example.com");

        assertNull(result);
    }

    /**
     * When a database exception occurs the method must return null gracefully.
     */
    @Test
    public void testDbLookupReturnsNullOnException() throws Exception {
        when(mockConnection.prepareStatement(anyString())).thenThrow(new java.sql.SQLException("DB error"));

        String result = database.db_lookup("anything");

        assertNull(result);
    }
}
