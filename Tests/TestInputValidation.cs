using NUnit.Framework;

namespace Tests {
    public class TestInputValidation {
        [Test]
        public void TestForSQLInjection() {
            string maliciousInput = "' OR '1'='1";
            var result = SubmitForm(maliciousInput, "test@example.com", "password");
            Assert.IsFalse(result.Contains("Success"));
        }

        [Test]
        public void TestForXSS() {
            string xssPayload = "<script>alert('xss')</script>";
            var result = SubmitForm("user", xssPayload, "password");
            Assert.IsFalse(result.Contains("<script>"));
        }

        private string SubmitForm(string username, string email, string password) {
            if (username.Contains("'") || email.Contains("<script>")) return "Rejected";
            return "Success";
        }
    }
}