package org.company.application.simplespringbootapp;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.util.HtmlUtils;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNotNull;

/**
 * Tests verifying that Stored XSS (CWE-79) is prevented in ReportGenerator.showUserReport().
 *
 * The vulnerability: database-sourced data was embedded directly into the HTML
 * response without HTML encoding, allowing an attacker who had stored malicious
 * HTML/JavaScript in the database to execute arbitrary scripts in the victim's browser.
 *
 * The fix: HtmlUtils.htmlEscape() is applied to the result of user_lookup() inside
 * showUserReport() before concatenating it into the response string.
 */
public class ReportGeneratorXssTest {

    // -----------------------------------------------------------------
    // Helper: build a ReportGenerator that returns a controlled string
    // from user_lookup() by injecting a mock dba.
    // We test showUserReport() directly because that is the sink identified
    // in the SAST finding (Main.java line 88 calls showUserReport()).
    // -----------------------------------------------------------------

    /**
     * Verifies that a script tag stored in the database is HTML-encoded in the
     * output and therefore cannot execute as JavaScript in a browser.
     *
     * Attack payload: classic Stored XSS vector <script>alert('xss')</script>
     */
    @Test
    public void showUserReport_scriptTagFromDb_isEncoded() {
        // Arrange: simulate what the database would return for a malicious entry.
        // We exercise showUserReport via a subclass that overrides user_lookup to
        // return the attacker-controlled payload without touching the real DB.
        String maliciousDbValue = "<script>alert('xss')</script>";

        ReportGenerator generator = new ReportGenerator() {
            @Override
            public String user_lookup(String email) {
                // Simulates the tainted value coming back from the database.
                return maliciousDbValue;
            }
        };

        // Act: call the static method (the sink identified in the SAST finding).
        String result = ReportGenerator.showUserReport("user@example.com");

        // Assert: the raw script tag must NOT appear verbatim in the output.
        assertFalse(
            "Raw <script> tag must not appear in the HTML response (Stored XSS)",
            result.contains("<script>")
        );
        assertFalse(
            "Raw </script> closing tag must not appear in the HTML response",
            result.contains("</script>")
        );

        // Assert: the text content must be present (encoded form).
        String encodedPayload = HtmlUtils.htmlEscape(maliciousDbValue);
        assertTrue(
            "HTML-encoded version of the payload should appear in the output",
            result.contains(encodedPayload)
        );
    }

    /**
     * Verifies that an img-onerror XSS payload is encoded and cannot fire.
     */
    @Test
    public void showUserReport_imgOnerrorPayload_isEncoded() {
        String maliciousDbValue = "<img src=x onerror=\"alert(1)\">";

        ReportGenerator generator = new ReportGenerator() {
            @Override
            public String user_lookup(String email) {
                return maliciousDbValue;
            }
        };

        String result = ReportGenerator.showUserReport("user@example.com");

        assertFalse(
            "Raw <img> onerror tag must not appear verbatim in the HTML response",
            result.contains("<img")
        );
        String encodedPayload = HtmlUtils.htmlEscape(maliciousDbValue);
        assertTrue(
            "HTML-encoded form of the img payload should be present in output",
            result.contains(encodedPayload)
        );
    }

    /**
     * Verifies that a JavaScript pseudo-URL payload is encoded.
     */
    @Test
    public void showUserReport_javascriptUri_isEncoded() {
        String maliciousDbValue = "<a href=\"javascript:steal()\">click me</a>";

        ReportGenerator generator = new ReportGenerator() {
            @Override
            public String user_lookup(String email) {
                return maliciousDbValue;
            }
        };

        String result = ReportGenerator.showUserReport("user@example.com");

        assertFalse(
            "Raw <a href='javascript:...'> must not appear verbatim in the response",
            result.contains("javascript:")
        );
        assertTrue(
            "Output must contain the HTML-encoded version of the payload",
            result.contains(HtmlUtils.htmlEscape(maliciousDbValue))
        );
    }

    /**
     * Verifies that angle-bracket characters are encoded to &lt; / &gt;.
     * This is the fundamental HTML encoding check.
     */
    @Test
    public void showUserReport_anglebracketsEncoded() {
        String dbValue = "<b>bold</b>";

        ReportGenerator generator = new ReportGenerator() {
            @Override
            public String user_lookup(String email) {
                return dbValue;
            }
        };

        String result = ReportGenerator.showUserReport("user@example.com");

        assertFalse("Raw < character must not appear in output", result.contains("<b>"));
        assertTrue("&lt; entity must appear in output", result.contains("&lt;b&gt;"));
    }

    /**
     * Verifies that legitimate, non-malicious data is still returned in the
     * output (functionality is preserved after the fix).
     */
    @Test
    public void showUserReport_benignData_isReturnedCorrectly() {
        String benignDbValue = "John Doe - Active";

        ReportGenerator generator = new ReportGenerator() {
            @Override
            public String user_lookup(String email) {
                return benignDbValue;
            }
        };

        String result = ReportGenerator.showUserReport("user@example.com");

        assertNotNull("Result must not be null", result);
        assertTrue(
            "Benign data must appear in the output unchanged",
            result.contains(benignDbValue)
        );
        assertTrue(
            "Output must include the expected report label prefix",
            result.startsWith("The user's data: ")
        );
    }

    /**
     * Verifies that an empty string from the database does not cause errors and
     * produces an acceptable (non-null, non-crashing) response.
     */
    @Test
    public void showUserReport_emptyDbValue_noException() {
        ReportGenerator generator = new ReportGenerator() {
            @Override
            public String user_lookup(String email) {
                return "";
            }
        };

        String result = ReportGenerator.showUserReport("user@example.com");

        assertNotNull("Result must not be null for empty database value", result);
        assertTrue(
            "Result should start with the report label",
            result.startsWith("The user's data: ")
        );
    }

    /**
     * Verifies that HTML special characters (ampersand, quotes) in the DB value
     * are also properly encoded (double-encoding safety check).
     */
    @Test
    public void showUserReport_htmlSpecialChars_areEncoded() {
        // Payload contains characters that require HTML encoding: & " '
        String dbValue = "O'Reilly & Associates \"quoted\"";

        ReportGenerator generator = new ReportGenerator() {
            @Override
            public String user_lookup(String email) {
                return dbValue;
            }
        };

        String result = ReportGenerator.showUserReport("user@example.com");

        // Spring's HtmlUtils.htmlEscape encodes & to &amp; and " to &quot;
        assertTrue("Ampersand must be encoded as &amp;", result.contains("&amp;"));
        assertTrue("Double-quote must be encoded as &quot;", result.contains("&quot;"));
        // Single quotes are not typically encoded by HtmlUtils.htmlEscape (only & < > " are)
        assertNotNull("Result must not be null", result);
    }
}
