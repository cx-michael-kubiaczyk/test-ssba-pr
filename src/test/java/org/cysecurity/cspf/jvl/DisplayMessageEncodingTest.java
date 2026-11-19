package org.cysecurity.cspf.jvl;

import junit.framework.TestCase;
import org.apache.taglibs.standard.functions.Functions;

/**
 * Verifies the HTML encoding applied by DisplayMessage.jsp to the stored
 * sender, subject and msg values (JSTL fn:escapeXml).
 */
public class DisplayMessageEncodingTest extends TestCase
{
    public void testScriptTagIsEncoded()
    {
        String encoded = Functions.escapeXml("<script>alert(1)</script>");
        assertEquals("&lt;script&gt;alert(1)&lt;/script&gt;", encoded);
        assertFalse(encoded.contains("<"));
    }

    public void testEventHandlerAttributeBreakoutIsEncoded()
    {
        String encoded = Functions.escapeXml("\"><img src=x onerror=alert(1)>");
        assertFalse(encoded.contains("<"));
        assertFalse(encoded.contains(">"));
        assertFalse(encoded.contains("\""));
    }

    public void testAmpersandAndQuotesAreEncoded()
    {
        assertEquals("a &amp; b &#039;c&#039;", Functions.escapeXml("a & b 'c'"));
    }

    public void testPlainTextIsUnchanged()
    {
        assertEquals("Hello World 123", Functions.escapeXml("Hello World 123"));
    }

    public void testNullBecomesEmptyString()
    {
        assertEquals("", Functions.escapeXml(null));
    }
}
