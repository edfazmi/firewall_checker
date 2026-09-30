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
    def __init__(self, device: Device, user=None):
        self.device = device
        self.user = user
        self.api_service = FortiGateAPIService(device=self.device, user=self.user)
        self.scan_record = None
        self.findings_to_create = []
        self.risks_to_create = []
        self.active_rules = self._load_active_rules()

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
            ('POL_POTENTIALLY_MERGE', 'Potentially Merge Policy')
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

    def _assess_policy_risks(self, parsed_policies: List[Dict]):
        for pol in parsed_policies:
            factors = []
            severities_found = []
            
            target_name = f"Policy ID {pol['id']} ({pol['name']})"
            related_findings = [f for f in self.findings_to_create if f.element_name == target_name]
            
            for f in related_findings:
                if f.rule.name not in factors:
                    factors.append(f.rule.name)
                severities_found.append(f.rule.severity)

            if 'CRITICAL' in severities_found:
                severity = 'CRITICAL'
            elif 'HIGH' in severities_found:
                severity = 'HIGH'
            elif 'MEDIUM' in severities_found:
                severity = 'MEDIUM'
            elif 'LOW' in severities_found:
                severity = 'LOW'
            elif 'INFO' in severities_found:
                severity = 'INFO'
            else:
                severity = 'INFO'

            if not factors:
                factors.append("Konfigurasi beroperasi normal tanpa temuan konflik.")

            self.risks_to_create.append(PolicyRiskAssessment(
                scan=self.scan_record,
                policy_id=pol['id'],
                policy_name=pol['name'],
                severity=severity,
                contributing_factors=factors
            ))

    def _finalize_scan(self):
        if self.findings_to_create:
            Finding.objects.bulk_create(self.findings_to_create)
        if self.risks_to_create:
            PolicyRiskAssessment.objects.bulk_create(self.risks_to_create)

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

            rule_engine = RuleEngine(self.scan_record, self.active_rules)
            findings, parsed_policies = rule_engine.run_all_checks(
                policies, interfaces, addresses, services, policy_hits
            )
            self.findings_to_create.extend(findings)

            self._assess_policy_risks(parsed_policies)

            self._finalize_scan()
            return self.scan_record

        except FirewallAPIError as e:
            self.scan_record.status = 'FAILED'
            self.scan_record.error_message = str(e)
            self.scan_record.save()
            raise ComplianceEngineError(f"API Error: {str(e)}")
        except Exception as e:
            self.scan_record.status = 'FAILED'
            self.scan_record.error_message = f"Internal Error: {str(e)}"
            self.scan_record.save()
            logger.error(f"Engine Error: {str(e)}", exc_info=True)
            raise ComplianceEngineError("Terjadi kesalahan internal sistem saat scanning.")