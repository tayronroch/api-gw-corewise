from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from django.contrib.auth.models import User


class MplsApiSmokeTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username='tester', password='secret')
        self.client.force_authenticate(user=self.user)

    def test_intelligent_search_requires_query(self):
        url = '/api/mpls/search/'
        r = self.client.get(url)
        self.assertEqual(r.status_code, 400)

    def test_intelligent_search_basic(self):
        url = '/api/mpls/search/?q=test&limit=1'
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertIn('results', r.data)

    def test_vpn_report_empty(self):
        url = '/api/mpls/reports/vpn/'
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertIn('results', r.data)


class MplsLegacyHeadersTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username='tester', password='secret')
        self.client.force_authenticate(user=self.user)

    def test_legacy_search_has_deprecation_headers(self):
        url = '/api/mpls/legacy/api/search/?q=abc'
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["Deprecation"], "true")
        self.assertIn("Sunset", r)

    def test_legacy_customer_report_excel_headers(self):
        url = '/api/mpls/legacy/api/customer-report/excel/'
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["Deprecation"], "true")
        self.assertEqual(r['Content-Type'], 'application/vnd.ms-excel')

# Create your tests here.
