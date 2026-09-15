# compliance/models.py
from django.db import models
from django.utils.translation import gettext_lazy as _
from devices.models import Device

class ComplianceRule(models.Model):
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
        ('INFO', 'Info'),
    ]
    CATEGORY_CHOICES = [
        ('POLICY', 'Firewall Policy'),
        ('INTERFACE', 'Interface'),
        ('ROUTING', 'Routing'),
        ('ADDRESS', 'Address Object'),
        ('SERVICE', 'Service Object'),
        ('ADMIN', 'Administrator'),
    ]
    rule_code = models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=200)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)
    severity = models.CharField(max_length=15, choices=SEVERITY_CHOICES)
    description = models.TextField()
    impact = models.TextField()
    recommendation = models.TextField()
    is_active = models.BooleanField(default=True)
   
    class Meta:
        db_table = 'compliance_rules'

    def __str__(self):
        return f"[{self.rule_code}] {self.name}"

class ScanHistory(models.Model):
    STATUS_CHOICES = [
        ('RUNNING', 'Running'),
        ('SUCCESS', 'Success'),
        ('FAILED', 'Failed'),
    ]
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='scans')
    scan_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='RUNNING')
    error_message = models.TextField(blank=True, null=True)
    changes_detail = models.JSONField(default=dict, blank=True, null=True)

    class Meta:
        db_table = 'scan_histories'
        ordering = ['-scan_date']

class Finding(models.Model):
    scan = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, related_name='findings')
    rule = models.ForeignKey(ComplianceRule, on_delete=models.PROTECT, related_name='findings')
    element_name = models.CharField(max_length=255)
    element_details = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'scan_findings'

class PolicyRiskAssessment(models.Model):
    scan = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, related_name='policy_risks')
    policy_id = models.CharField(max_length=50)
    policy_name = models.CharField(max_length=200, blank=True, null=True)
    severity = models.CharField(max_length=20)
    contributing_factors = models.JSONField(default=list)

    class Meta:
        db_table = 'policy_risk_assessments'

class ConfigurationSnapshot(models.Model):
    device = models.OneToOneField(Device, on_delete=models.CASCADE, related_name='config_snapshot')
    policies_json = models.JSONField(default=dict)
    last_updated = models.DateTimeField(auto_now=True)

