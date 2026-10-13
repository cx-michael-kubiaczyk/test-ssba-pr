package org.company.application.simplespringbootapp;

import org.junit.Test;
import org.junit.Before;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

/**
 * Tests for dba.db_lookup() to verify parameterized queries are used
 * (SQL injection remediation — CWE-89).
 *
 * The key assertion in each test is that Connection.prepareStatement() is
 * called with a static SQL template containing a '?' placeholder, and that
 * the user-supplied value is bound via PreparedStatement.setString() rather
 * than concatenated directly into the query string.
 */
public class DbaTest {

    @Mock
    private Connection mockConnection;

    @Mock
    private PreparedStatement mockPreparedStatement;

    @Mock
    private ResultSet mockResultSet;

    private dba dbInstance;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        // Wire the mock chain: connection → preparedStatement → resultSet
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery()).thenReturn(mockResultSet);

        dbInstance = new dba();
        // Inject the mock connection directly (init() guards on a hard-coded
        // password; we bypass that by setting the field via a helper ctor
        // or — since there is none — by using reflection as the most
        // practical option in this project).
        java.lang.reflect.Field connectField = dba.class.getDeclaredField("connect");
        connectField.setAccessible(true);
        connectField.set(dbInstance, mockConnection);
    }

    /**
     * Happy-path: a normal email address should be passed via setString(),
     * not embedded in the SQL string.
     */
    @Test
    public void testNormalEmailUsesParameterizedQuery() throws Exception {
        String email = "user@example.com";

        dbInstance.db_lookup(email);

        // The static query template (with placeholder) must be prepared
        verify(mockConnection).prepareStatement("select * from somewhere where something=?");
        // The actual value must be bound via setString, NOT concatenated
        verify(mockPreparedStatement).setString(1, email);
        // executeQuery must be called without arguments (parameterized form)
        verify(mockPreparedStatement).executeQuery();
    }

    /**
     * SQL injection attempt: a classic single-quote payload that would break
     * a concatenated query must still be passed safely as a parameter.
     *
     * With string concatenation the query would become:
     *   select * from somewhere where something='' OR '1'='1'
     * With a PreparedStatement the payload is treated as a literal value,
     * so the query structure is never altered.
     */
    @Test
    public void testSqlInjectionPayloadIsPassedAsParameter() throws Exception {
        String maliciousInput = "' OR '1'='1";

        dbInstance.db_lookup(maliciousInput);

        // The SQL template must NOT contain the user input
        verify(mockConnection).prepareStatement("select * from somewhere where something=?");
        // The malicious value must be bound, not concatenated
        verify(mockPreparedStatement).setString(1, maliciousInput);
        verify(mockPreparedStatement).executeQuery();
    }

    /**
     * SQL injection attempt: UNION-based extraction payload.
     */
    @Test
    public void testUnionBasedInjectionPayloadIsPassedAsParameter() throws Exception {
        String unionPayload = "x' UNION SELECT table_name,2,3 FROM information_schema.tables--";

        dbInstance.db_lookup(unionPayload);

        verify(mockConnection).prepareStatement("select * from somewhere where something=?");
        verify(mockPreparedStatement).setString(1, unionPayload);
        verify(mockPreparedStatement).executeQuery();
    }

    /**
     * SQL injection attempt: stacked-query (multiple statements) payload.
     */
    @Test
    public void testStackedQueryPayloadIsPassedAsParameter() throws Exception {
        String stackedPayload = "x'; DROP TABLE users; --";

        dbInstance.db_lookup(stackedPayload);

        verify(mockConnection).prepareStatement("select * from somewhere where something=?");
        verify(mockPreparedStatement).setString(1, stackedPayload);
        verify(mockPreparedStatement).executeQuery();
    }

    /**
     * Verify that prepareStatement() is NEVER called with user-controlled
     * data embedded directly in the SQL string (i.e., no concatenation).
     *
     * We confirm that no call to prepareStatement was made with a string
     * that contains the injected payload.
     */
    @Test
    public void testPrepareStatementNeverReceivesUserInput() throws Exception {
        String maliciousInput = "evil' OR 1=1 --";

        dbInstance.db_lookup(maliciousInput);

        // The only argument allowed is the static template
        verify(mockConnection, times(1)).prepareStatement("select * from somewhere where something=?");
        // Ensure prepareStatement was NOT called with any string containing
        // the user's raw input directly embedded
        verify(mockConnection, never()).prepareStatement(contains(maliciousInput));
    }

    /**
     * Null input should not cause prepareStatement to embed "null" literally
     * in the SQL; it must still use setString(1, null).
     */
    @Test
    public void testNullInputIsPassedAsParameter() throws Exception {
        dbInstance.db_lookup(null);

        verify(mockConnection).prepareStatement("select * from somewhere where something=?");
        verify(mockPreparedStatement).setString(1, null);
        verify(mockPreparedStatement).executeQuery();
    }
}
