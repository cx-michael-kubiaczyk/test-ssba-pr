package org.company.application.simplespringbootapp;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Tests for the dba class, focusing on the SQL injection remediation.
 *
 * The fix replaced Statement + string concatenation with PreparedStatement
 * parameterized queries, so user-supplied data is always bound as a
 * parameter and never interpolated into the SQL string.
 */
public class DbaTest {

    private dba dbaInstance;
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private ResultSet mockResultSet;

    @BeforeEach
    public void setUp() throws Exception {
        dbaInstance = new dba();

        mockConnection = mock(Connection.class);
        mockPreparedStatement = mock(PreparedStatement.class);
        mockResultSet = mock(ResultSet.class);

        // Inject the mock Connection directly into the private field
        // (init() uses a legacy password check we cannot call in tests)
        Field connectField = dba.class.getDeclaredField("connect");
        connectField.setAccessible(true);
        connectField.set(dbaInstance, mockConnection);
    }

    // ------------------------------------------------------------------
    // Positive / functional tests
    // ------------------------------------------------------------------

    /**
     * A normal lookup returns the first column of the first result row.
     */
    @Test
    public void testDbLookupReturnsValueOnHit() throws Exception {
        String input = "user@example.com";
        String expected = "resultValue";

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true);
        when(mockResultSet.getString(1)).thenReturn(expected);

        String result = dbaInstance.db_lookup(input);

        assertEquals(expected, result, "db_lookup should return the first column value when a row exists");
    }

    /**
     * When no row is found the method returns null (not an exception).
     */
    @Test
    public void testDbLookupReturnsNullOnMiss() throws Exception {
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(false);

        String result = dbaInstance.db_lookup("nobody@example.com");

        assertNull(result, "db_lookup should return null when the result set is empty");
    }

    // ------------------------------------------------------------------
    // Security / SQL-injection tests
    // ------------------------------------------------------------------

    /**
     * Verify that db_lookup uses PreparedStatement (not Statement) and binds
     * the user-supplied value via setString — never by string concatenation.
     *
     * If the code still used Statement.executeQuery(sql) the mock for
     * prepareStatement would never be called, and the assertion below would fail.
     */
    @Test
    public void testDbLookupUsesPreparedStatement() throws Exception {
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(false);

        dbaInstance.db_lookup("test@example.com");

        // The connection must have been asked to prepare a statement
        verify(mockConnection, times(1)).prepareStatement(anyString());
        // The user value must have been bound as parameter 1, not concatenated
        verify(mockPreparedStatement, times(1)).setString(1, "test@example.com");
    }

    /**
     * A classic SQL injection payload must not alter the query structure.
     * The value is bound as a literal string parameter, so the DB receives
     * it as data, not as SQL syntax.
     *
     * If string concatenation were still used, the mock for prepareStatement
     * would receive a query like:
     *   "select * from somewhere where something='' OR '1'='1'"
     * With parameterization the query string is always the fixed template,
     * and the payload is safely bound via setString.
     */
    @Test
    public void testSqlInjectionPayloadIsBoundAsParameter() throws Exception {
        String sqlInjectionPayload = "' OR '1'='1";

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(false);

        dbaInstance.db_lookup(sqlInjectionPayload);

        // The query template passed to prepareStatement must NOT contain
        // the injected payload — it should only contain the placeholder '?'
        verify(mockConnection).prepareStatement(argThat(sql ->
                sql.contains("?") && !sql.contains(sqlInjectionPayload)
        ));
        // The payload must be bound as a parameter, not concatenated
        verify(mockPreparedStatement, times(1)).setString(1, sqlInjectionPayload);
    }

    /**
     * A UNION-based injection payload must be treated as a bound parameter.
     */
    @Test
    public void testUnionInjectionPayloadIsBoundAsParameter() throws Exception {
        String unionPayload = "x' UNION SELECT password FROM users--";

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(false);

        dbaInstance.db_lookup(unionPayload);

        verify(mockConnection).prepareStatement(argThat(sql ->
                sql.contains("?") && !sql.contains("UNION")
        ));
        verify(mockPreparedStatement, times(1)).setString(1, unionPayload);
    }

    /**
     * A DROP TABLE injection payload must be treated as a bound parameter.
     */
    @Test
    public void testDropTableInjectionPayloadIsBoundAsParameter() throws Exception {
        String dropPayload = "'; DROP TABLE somewhere;--";

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(false);

        dbaInstance.db_lookup(dropPayload);

        verify(mockConnection).prepareStatement(argThat(sql ->
                sql.contains("?") && !sql.contains("DROP")
        ));
        verify(mockPreparedStatement, times(1)).setString(1, dropPayload);
    }

    /**
     * Null input must not cause an unhandled NullPointerException;
     * the method must return null gracefully.
     */
    @Test
    public void testNullInputHandledGracefully() throws Exception {
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(false);

        // Should not throw
        String result = assertDoesNotThrow(() -> dbaInstance.db_lookup(null));
        assertNull(result);
    }

    /**
     * An empty string is a valid parameter value; no result row means null.
     */
    @Test
    public void testEmptyStringInputHandledGracefully() throws Exception {
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(false);

        String result = dbaInstance.db_lookup("");

        assertNull(result);
        verify(mockPreparedStatement, times(1)).setString(1, "");
    }

    /**
     * When the underlying JDBC call throws an exception the method must
     * return null rather than propagating the exception to the caller.
     */
    @Test
    public void testDbExceptionReturnsNull() throws Exception {
        when(mockConnection.prepareStatement(anyString())).thenThrow(new java.sql.SQLException("connection error"));

        String result = assertDoesNotThrow(() -> dbaInstance.db_lookup("test@example.com"));
        assertNull(result);
    }
}
