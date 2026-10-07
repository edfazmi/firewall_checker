import logging
from typing import Dict, List
from django.utils import timezone
from core.services import BaseService
from core.exceptions import ComplianceEngineError, FirewallAPIError
from devices.models import Device
from devices.services import FortiGateAPIService
from compliance.models import ComplianceRule, ScanHistory, Finding, PolicyRiskAssessment

from .rules import RuleEngine


logger = logging.getLogger('application')

class ComplianceScanner(BaseService):
    FINDING_BATCH_SIZE = 500
    def __init__(self, device: Device, user=None):
        self.device = device
        self.user = user
        self.api_service = FortiGateAPIService(device=self.device, user=self.user)
        self.scan_record = None
        self.findings_to_create = []
        self.risks_to_create = []
        self.active_rules = self._load_active_rules()

    def _store_finding_batch(self, findings):
        if findings:
            Finding.objects.bulk_create(findings, batch_size=self.FINDING_BATCH_SIZE)

    def _load_active_rules(self) -> Dict[str, ComplianceRule]:
        core_rules = [
            ('POL_OVERLY_PERMISSIVE', 'Overly Permissive Policy (ANY/ALL)'),
            ('POL_ANY_INTF', 'Overly Permissive Interface (ANY)'),
            ('POL_ANY_SVC', 'Overly Permissive Service (ALL)'),
            ('POL_UNUSED', 'Potentially Unused Policy'),
            ('POL_SHADOWED', 'Shadowed Policy (Tertimpa Urutan)'),
            ('POL_REDUNDANT', 'Potentially Redundant Policy'),
            ('POL_CONFLICT', 'Conflicting Policy'),
            ('POL_DUPLICATE', 'Duplicate Policy'),
            ('POL_NO_DESC', 'Policy without Description/Comment'),
            ('INTF_DOWN', 'Interface Down'),
            ('INTF_NO_IP', 'Interface Active Without IP'),
            ('ADDR_DUP_SUBNET', 'Duplicate Address Object'),
            ('SVC_WIDE_PORT', 'Wide Port Range Service'),
            ('POL_NO_LOG', 'Logging Policy Disabled'),
            ('POL_POTENTIALLY_MERGE', 'Potentially Merge Policy'),
            ('POL_NOT_USED_1MONTH', 'Potentially Inactive Policy (Last Used >= 1 Month)')
        ]
        
        for code, name in core_rules:
            ComplianceRule.objects.get_or_create(
                rule_code=code,
                defaults={
                    'name': name,
                    'is_active': True
                }
            )
        
        rules = ComplianceRule.objects.filter(is_active=True)
        return {rule.rule_code.strip(): rule for rule in rules}

    def _assess_policy_risks(self, parsed_policies: List[Dict], risk_index: Dict[str, Dict]):
        severity_order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        for pol in parsed_policies:
            target_name = f"Policy ID {pol['id']} ({pol['name']})"
            risk_data = risk_index.get(target_name, {})
            factors = list(risk_data.get("factors", []))
            severities_found = [str(value).upper() for value in risk_data.get("severities", [])]
            severity = next((level for level in severity_order if level in severities_found), "INFO")
            if not factors:
                factors.append("Konfigurasi beroperasi normal tanpa temuan konflik.")
            self.risks_to_create.append(
                PolicyRiskAssessment(
                    scan=self.scan_record,
                    policy_id=pol['id'],
                    policy_name=pol['name'],
                    severity=severity,
                    contributing_factors=factors
                )
            )

    def _finalize_scan(self):
        if self.findings_to_create:
            self._store_finding_batch(self.findings_to_create)
            self.findings_to_create = []
        if self.risks_to_create:
            PolicyRiskAssessment.objects.bulk_create(self.risks_to_create, batch_size=self.FINDING_BATCH_SIZE)
        self.scan_record.status = 'SUCCESS'
        self.scan_record.save(update_fields=['status'])
        self.device.last_sync = timezone.now()
        self.device.save(update_fields=['last_sync'])
        if hasattr(self, 'log_action'):
            self.log_action('info', "Scan sukses diselesaikan.")

    def execute_scan(self) -> ScanHistory:
        ScanHistory.objects.filter(device=self.device).delete()
        self.scan_record = ScanHistory.objects.create(device=self.device, status='RUNNING')

        try:
            policies = self.api_service.get_firewall_policies()
            interfaces = self.api_service.get_interfaces()
            addresses = self.api_service.get_address_objects()
            services = self.api_service.get_service_objects()
            policy_hits = self.api_service.get_policy_monitor()

            rule_engine = RuleEngine(
                self.scan_record,
                self.active_rules,
                finding_sink=self._store_finding_batch,
                finding_batch_size=self.FINDING_BATCH_SIZE,
            )
            _, parsed_policies = rule_engine.run_all_checks(
                policies, interfaces, addresses, services, policy_hits
            )
            self._assess_policy_risks(parsed_policies, rule_engine.risk_index)

            self._finalize_scan()
            return self.scan_record

        except FirewallAPIError as e:
            Finding.objects.filter(scan=self.scan_record).delete()
            PolicyRiskAssessment.objects.filter(scan=self.scan_record).delete()
            self.scan_record.status = 'FAILED'
            self.scan_record.error_message = str(e)
            self.scan_record.save()
            raise ComplianceEngineError(f"API Error: {str(e)}")
        except Exception as e:
            Finding.objects.filter(scan=self.scan_record).delete()
            PolicyRiskAssessment.objects.filter(scan=self.scan_record).delete()
            self.scan_record.status = 'FAILED'
            self.scan_record.error_message = f"Internal Error: {str(e)}"
            self.scan_record.save()
            logger.error(f"Engine Error: {str(e)}", exc_info=True)
            raise ComplianceEngineError("Terjadi kesalahan internal sistem saat scanning.")
