import logging
from typing import Dict, List
from django.utils import timezone
from core.services import BaseService
from core.exceptions import ComplianceEngineError, FortiGateAPIError
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
            ('POL_OVERLY_PERMISSIVE', 'Overly Permissive Policy (ANY/ALL)', 'Policy mengizinkan trafik dengan cakupan Source atau Destination terbuka sangat luas (ANY/ALL).', 'HIGH', 'Ganti objek "all" dengan spesifik IP Address, Subnet, atau Address Group.'),
            ('POL_ANY_INTF', 'Overly Permissive Interface (ANY)', 'Policy mengizinkan trafik dengan cakupan Incoming atau Outgoing Interface terbuka untuk semua (ANY).', 'HIGH', 'Spesifikasikan Incoming dan Outgoing interface yang diizinkan untuk melewati policy ini.'),
            ('POL_ANY_SVC', 'Overly Permissive Service (ALL)', 'Policy mengizinkan trafik untuk semua layanan/port (ALL).', 'HIGH', 'Spesifikasikan layanan atau port yang benar-benar dibutuhkan.'),
            ('POL_UNUSED', 'Potentially Unused Policy', 'Firewall policy dalam status aktif namun tercatat memiliki 0 Hit (tidak pernah dilalui traffic).', 'INFO', 'Lakukan review bisnis. Policy ini mungkin perlu dinonaktifkan.'),
            ('POL_SHADOWED', 'Shadowed Policy (Tertimpa Urutan)', 'Policy spesifik diletakkan di bawah policy umum yang memiliki Action berlawanan, sehingga tidak akan pernah dieksekusi.', 'CRITICAL', 'Pindahkan letak Policy ini ke urutan di atas Policy yang membayanginya.'),
            ('POL_REDUNDANT', 'Potentially Redundant Policy', 'Subnet jaringan sepenuhnya tercakup di dalam policy lain yang memiliki action yang sama.', 'MEDIUM', 'Hapus Policy ini karena traffic-nya sudah diizinkan/diblokir secara lebih luas oleh policy lain.'),
            ('POL_CONFLICT', 'Conflicting Policy', 'Terdapat bentrokan parsial (overlap) pada cakupan IP address dengan policy lain yang memiliki Action berlawanan.', 'MEDIUM', 'Pisahkan subnet yang bentrok menjadi policy independen.'),
            ('POL_DUPLICATE', 'Duplicate Policy', 'Terdapat duplikasi identik dengan policy lain (Source, Dest, Service, dan Action sama).', 'MEDIUM', 'Hapus salah satu policy yang menduplikat.'),
            ('POL_NO_DESC', 'Policy without Description/Comment', 'Policy tidak memiliki komentar atau deskripsi.', 'LOW', 'Tambahkan komentar yang menjelaskan tujuan bisnis dari policy tersebut.'),
            ('INTF_DOWN', 'Interface Down', 'Interface dalam keadaan admin down.', 'INFO', 'Verifikasi apakah interface ini masih dibutuhkan.'),
            ('INTF_NO_IP', 'Interface Active Without IP', 'Interface berstatus UP namun tidak memiliki konfigurasi IP.', 'LOW', 'Berikan IP Address atau nonaktifkan interface jika tidak digunakan.'),
            ('ADM_NO_TRUSTHOST', 'Admin tanpa Trusted Host', 'Akun administrator dapat diakses dari IP manapun tanpa pembatasan.', 'HIGH', 'Konfigurasi Trusted Host (Restricted IP) untuk akun administrator.'),
            ('ROUTE_NO_DEFAULT', 'Missing Default Route', 'Tidak ada static route default (0.0.0.0/0) yang aktif.', 'MEDIUM', 'Pastikan firewall memiliki rute keluar (gateway) yang valid.'),
            ('ADDR_DUP_SUBNET', 'Duplicate Address Object', 'Terdapat objek address berbeda yang menunjuk ke subnet yang sama persis.', 'LOW', 'Gabungkan atau hapus objek address yang berulang.'),
            ('SVC_WIDE_PORT', 'Wide Port Range Service', 'Service membuka rentang port yang sangat besar (1-65535).', 'LOW', 'Persempit rentang port sesuai kebutuhan aplikasi.'),
            ('POL_NO_LOG', 'Logging Policy Disabled', 'Fitur pencatatan log pada policy tidak diaktifkan.', 'MEDIUM', 'Aktifkan Log Allowed Traffic, minimal untuk Security Events.')
        ]
        
        for code, name, desc, sev, rec in core_rules:
            ComplianceRule.objects.get_or_create(
                rule_code=code,
                defaults={
                    'name': name,
                    'description': desc,
                    'severity': sev,
                    'recommendation': rec,
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
            admins = self.api_service.get_administrators()
            routes = self.api_service.get_static_routes()
            addresses = self.api_service.get_address_objects()
            services = self.api_service.get_service_objects()
            policy_hits = self.api_service.get_policy_monitor()
            
            recent_admin = self.api_service.get_recent_admin() if hasattr(self.api_service, 'get_recent_admin') else "Unknown"

            rule_engine = RuleEngine(self.scan_record, self.active_rules)
            findings, parsed_policies = rule_engine.run_all_checks(
                policies, interfaces, admins, routes, addresses, services, policy_hits
            )
            self.findings_to_create.extend(findings)

            self._assess_policy_risks(parsed_policies)

            self._finalize_scan()
            return self.scan_record

        except FortiGateAPIError as e:
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