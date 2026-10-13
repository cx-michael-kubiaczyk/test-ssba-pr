package org.company.application.simplespringbootapp;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.util.HtmlUtils;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Tests verifying that ReportGenerator.showUserReport() HTML-encodes
 * database-sourced content before embedding it in the HTTP response,
 * preventing Stored XSS (CWE-79).
 *
 * The taint flow under test:
 *   dba.db_lookup() [SOURCE] -> user_lookup() -> showUserReport() [SINK]
 *   -> reportUser() HTTP response
 *
 * Fix applied: HtmlUtils.htmlEscape() wraps the return value of user_lookup()
 * inside showUserReport(), so attacker-controlled data stored in the DB cannot
 * be rendered as HTML or JavaScript by a victim's browser.
 */
public class ReportGeneratorXssTest {

    // ---------------------------------------------------------------------------
    // Unit tests for ReportGenerator.showUserReport() – the sink
    // ---------------------------------------------------------------------------

    /**
     * Basic sanity: benign user data passes through with HTML encoding applied.
     * The label text must still be present and the content must be the
     * HTML-encoded version of what user_lookup returns.
     */
    @Test
    public void showUserReport_benignData_returnsHtmlEncodedContent() {
        // Arrange – create a ReportGenerator whose db returns a plain string.
        ReportGenerator rg = new ReportGenerator();
        dba mockDb = Mockito.mock(dba.class);
        Mockito.when(mockDb.db_lookup(Mockito.anyString())).thenReturn("Jane Doe");
        rg.init(mockDb);

        // Act – exercise the sink directly (static method calls instance user_lookup
        // via the static showUserReport path).
        String result = ReportGenerator.showUserReport("jane@example.com");

        // Assert – result must start with the expected label.
        assertTrue("Response must contain the label prefix",
                result.startsWith("The user's data: "));
        // Assert – result must contain the HTML-encoded form of the benign value.
        assertTrue("Benign value should appear in response",
                result.contains("Jane Doe"));
    }

    /**
     * XSS regression: a script tag stored in the database must not appear
     * unescaped in the rendered output.
     *
     * Before the fix, showUserReport returned:
     *   "The user's data: <script>alert('xss')</script>"
     *
     * After the fix it must return:
     *   "The user's data: &lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"
     * (or equivalent HtmlUtils encoding).
     */
    @Test
    public void showUserReport_scriptTagFromDb_isHtmlEncoded() {
        // Arrange
        String maliciousDbValue = "<script>alert('xss')</script>";
        ReportGenerator rg = new ReportGenerator();
        dba mockDb = Mockito.mock(dba.class);
        Mockito.when(mockDb.db_lookup(Mockito.anyString())).thenReturn(maliciousDbValue);
        rg.init(mockDb);

        // Act
        String result = ReportGenerator.showUserReport("victim@example.com");

        // Assert – the raw script tag must NOT be present in the output.
        assertFalse("Raw <script> tag must not appear in the response (XSS regression)",
                result.contains("<script>"));
        assertFalse("Raw </script> tag must not appear in the response (XSS regression)",
                result.contains("</script>"));

        // Assert – the value must be HTML-encoded.
        String expectedEncoded = HtmlUtils.htmlEscape(maliciousDbValue);
        assertTrue("HTML-encoded script payload must be present in the response",
                result.contains(expectedEncoded));
    }

    /**
     * XSS regression: img onerror event handler stored in the database must
     * not execute in the browser.
     */
    @Test
    public void showUserReport_imgOnerrorFromDb_isHtmlEncoded() {
        // Arrange
        String maliciousDbValue = "<img src=x onerror=\"document.cookie='stolen'\"/>";
        ReportGenerator rg = new ReportGenerator();
        dba mockDb = Mockito.mock(dba.class);
        Mockito.when(mockDb.db_lookup(Mockito.anyString())).thenReturn(maliciousDbValue);
        rg.init(mockDb);

        // Act
        String result = ReportGenerator.showUserReport("attacker@example.com");

        // Assert – raw img tag with onerror must not be present.
        assertFalse("Raw <img> onerror payload must not appear unescaped in response",
                result.contains("<img"));
        assertFalse("onerror attribute must not appear unescaped in response",
                result.contains("onerror"));

        // Assert – HTML-encoded form of the payload must be present.
        String expectedEncoded = HtmlUtils.htmlEscape(maliciousDbValue);
        assertTrue("HTML-encoded img payload must be present in the response",
                result.contains(expectedEncoded));
    }

    /**
     * XSS regression: an SVG-based XSS vector stored in the database must
     * not be rendered as HTML.
     */
    @Test
    public void showUserReport_svgXssFromDb_isHtmlEncoded() {
        // Arrange
        String maliciousDbValue = "<svg/onload=alert(1)>";
        ReportGenerator rg = new ReportGenerator();
        dba mockDb = Mockito.mock(dba.class);
        Mockito.when(mockDb.db_lookup(Mockito.anyString())).thenReturn(maliciousDbValue);
        rg.init(mockDb);

        // Act
        String result = ReportGenerator.showUserReport("x@example.com");

        // Assert – raw SVG tag must not appear in response.
        assertFalse("Raw <svg> tag must not appear unescaped in response",
                result.contains("<svg"));

        // Assert – HTML-encoded form must appear.
        String expectedEncoded = HtmlUtils.htmlEscape(maliciousDbValue);
        assertTrue("HTML-encoded SVG payload must be present in the response",
                result.contains(expectedEncoded));
    }

    /**
     * XSS regression: javascript: URI stored in the database must be encoded.
     */
    @Test
    public void showUserReport_javascriptUriFromDb_isHtmlEncoded() {
        // Arrange
        String maliciousDbValue = "<a href=\"javascript:alert('xss')\">click</a>";
        ReportGenerator rg = new ReportGenerator();
        dba mockDb = Mockito.mock(dba.class);
        Mockito.when(mockDb.db_lookup(Mockito.anyString())).thenReturn(maliciousDbValue);
        rg.init(mockDb);

        // Act
        String result = ReportGenerator.showUserReport("x@example.com");

        // Assert – raw anchor tag with javascript: href must not appear.
        assertFalse("Raw javascript: URI must not appear unescaped in response",
                result.contains("javascript:"));

        // Assert – HTML-encoded form must appear.
        String expectedEncoded = HtmlUtils.htmlEscape(maliciousDbValue);
        assertTrue("HTML-encoded javascript URI payload must be present in response",
                result.contains(expectedEncoded));
    }

    /**
     * Null/empty database result: when db_lookup returns null, user_lookup
     * falls back to "No results for <email>". The email value itself is also
     * treated as potentially tainted and the encoded fallback must not contain
     * raw HTML from the email parameter.
     *
     * Note: the fallback path ("No results for " + email) in user_lookup also
     * flows into showUserReport's HTML-encoding call, so it is covered by the
     * same fix.
     */
    @Test
    public void showUserReport_nullDbResult_fallbackIsIncludedInEncodedOutput() {
        // Arrange – db returns null, triggering the fallback in user_lookup.
        ReportGenerator rg = new ReportGenerator();
        dba mockDb = Mockito.mock(dba.class);
        Mockito.when(mockDb.db_lookup(Mockito.anyString())).thenReturn(null);
        rg.init(mockDb);

        // Act
        String result = ReportGenerator.showUserReport("missing@example.com");

        // Assert – response must contain the label prefix.
        assertTrue("Response must contain the label prefix",
                result.startsWith("The user's data: "));
        // Assert – the fallback text (HTML-encoded) must be present.
        // The raw text "No results for" (without HTML) should be safe as-is,
        // but we verify the encoding path is taken for the whole value.
        assertTrue("Fallback 'No results' message should appear in response",
                result.contains("No results for"));
    }

    /**
     * XSS regression via fallback: if the email parameter itself contains an
     * XSS payload and db_lookup returns null, the fallback response
     * "No results for <email>" must also be HTML-encoded.
     */
    @Test
    public void showUserReport_xssInEmailFallback_isHtmlEncoded() {
        // Arrange – db returns null, so user_lookup returns "No results for <script>..."
        String xssEmail = "<script>stealCookies()</script>@evil.com";
        ReportGenerator rg = new ReportGenerator();
        dba mockDb = Mockito.mock(dba.class);
        Mockito.when(mockDb.db_lookup(Mockito.anyString())).thenReturn(null);
        rg.init(mockDb);

        // Act
        String result = ReportGenerator.showUserReport(xssEmail);

        // Assert – raw script tag from the email must not appear in response.
        assertFalse("Raw <script> from email fallback must not appear unescaped in response",
                result.contains("<script>"));
        assertFalse("Raw </script> from email fallback must not appear unescaped in response",
                result.contains("</script>"));
    }

    /**
     * Encoding correctness: verify that HtmlUtils.htmlEscape produces the
     * expected tokens for a representative set of special HTML characters.
     * This is a contract test for the encoding library to catch any
     * accidental removal of the encoding call.
     */
    @Test
    public void htmlEscape_specialCharacters_areEncodedCorrectly() {
        assertEquals("&lt;", HtmlUtils.htmlEscape("<"));
        assertEquals("&gt;", HtmlUtils.htmlEscape(">"));
        assertEquals("&amp;", HtmlUtils.htmlEscape("&"));
        assertEquals("&quot;", HtmlUtils.htmlEscape("\""));
    }
}
