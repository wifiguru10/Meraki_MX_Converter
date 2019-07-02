# -*- coding: utf-8 -*-

"""
    meraki

    This file was automatically generated for meraki by APIMATIC v2.0 ( https://apimatic.io ).
"""

from meraki.decorators import lazy_property
from meraki.configuration import Configuration
from meraki.controllers.organizations_controller import OrganizationsController
from meraki.controllers.mx1_many_nat_rules_controller import MX1ManyNATRulesController
from meraki.controllers.firewalled_services_controller import FirewalledServicesController
from meraki.controllers.traffic_shaping_controller import TrafficShapingController
from meraki.controllers.wireless_health_controller import WirelessHealthController
from meraki.controllers.alert_settings_controller import AlertSettingsController
from meraki.controllers.admins_controller import AdminsController
from meraki.controllers.action_batches_controller import ActionBatchesController
from meraki.controllers.switch_ports_controller import SwitchPortsController
from meraki.controllers.ssids_controller import SsidsController
from meraki.controllers.splash_settings_controller import SplashSettingsController
from meraki.controllers.splash_login_attempts_controller import SplashLoginAttemptsController
from meraki.controllers.sm_controller import SMController
from meraki.controllers.named_tag_scope_controller import NamedTagScopeController
from meraki.controllers.saml_roles_controller import SAMLRolesController
from meraki.controllers.pii_controller import PIIController
from meraki.controllers.open_api_spec_controller import OpenAPISpecController
from meraki.controllers.management_interface_settings_controller import ManagementInterfaceSettingsController
from meraki.controllers.mrl3_firewall_controller import MRL3FirewallController
from meraki.controllers.mxl7_firewall_controller import MXL7FirewallController
from meraki.controllers.group_policies_controller import GroupPoliciesController
from meraki.controllers.networks_controller import NetworksController
from meraki.controllers.mv_sense_controller import MVSenseController
from meraki.controllers.vlans_controller import VlansController
from meraki.controllers.uplink_settings_controller import UplinkSettingsController
from meraki.controllers.static_routes_controller import StaticRoutesController
from meraki.controllers.mx_port_forwarding_rules_controller import MXPortForwardingRulesController
from meraki.controllers.mx11_nat_rules_controller import MX11NATRulesController
from meraki.controllers.content_filtering_rules_controller import ContentFilteringRulesController
from meraki.controllers.content_filtering_categories_controller import ContentFilteringCategoriesController
from meraki.controllers.syslog_servers_controller import SyslogServersController
from meraki.controllers.switch_stacks_controller import SwitchStacksController
from meraki.controllers.switch_profiles_controller import SwitchProfilesController
from meraki.controllers.switch_settings_controller import SwitchSettingsController
from meraki.controllers.snmp_settings_controller import SNMPSettingsController
from meraki.controllers.malware_settings_controller import MalwareSettingsController
from meraki.controllers.intrusion_settings_controller import IntrusionSettingsController
from meraki.controllers.radio_settings_controller import RadioSettingsController
from meraki.controllers.clients_controller import ClientsController
from meraki.controllers.api_usage_controller import APIUsageController
from meraki.controllers.net_flow_settings_controller import NetFlowSettingsController
from meraki.controllers.meraki_auth_users_controller import MerakiAuthUsersController
from meraki.controllers.http_servers_controller import HTTPServersController
from meraki.controllers.mxvpn_firewall_controller import MXVPNFirewallController
from meraki.controllers.mxl7_application_categories_controller import MXL7ApplicationCategoriesController
from meraki.controllers.mxl3_firewall_controller import MXL3FirewallController
from meraki.controllers.mx_cellular_firewall_controller import MXCellularFirewallController
from meraki.controllers.devices_controller import DevicesController
from meraki.controllers.config_templates_controller import ConfigTemplatesController
from meraki.controllers.cameras_controller import CamerasController
from meraki.controllers.bluetooth_clients_controller import BluetoothClientsController
from meraki.controllers.security_events_controller import SecurityEventsController
from meraki.controllers.webhook_logs_controller import WebhookLogsController


class MerakiClient(object):

    config = Configuration

    @lazy_property
    def organizations(self):
        return OrganizationsController()

    @lazy_property
    def mx_1_many_nat_rules(self):
        return MX1ManyNATRulesController()

    @lazy_property
    def firewalled_services(self):
        return FirewalledServicesController()

    @lazy_property
    def traffic_shaping(self):
        return TrafficShapingController()

    @lazy_property
    def wireless_health(self):
        return WirelessHealthController()

    @lazy_property
    def alert_settings(self):
        return AlertSettingsController()

    @lazy_property
    def admins(self):
        return AdminsController()

    @lazy_property
    def action_batches(self):
        return ActionBatchesController()

    @lazy_property
    def switch_ports(self):
        return SwitchPortsController()

    @lazy_property
    def ssids(self):
        return SsidsController()

    @lazy_property
    def splash_settings(self):
        return SplashSettingsController()

    @lazy_property
    def splash_login_attempts(self):
        return SplashLoginAttemptsController()

    @lazy_property
    def sm(self):
        return SMController()

    @lazy_property
    def named_tag_scope(self):
        return NamedTagScopeController()

    @lazy_property
    def saml_roles(self):
        return SAMLRolesController()

    @lazy_property
    def pii(self):
        return PIIController()

    @lazy_property
    def open_api_spec(self):
        return OpenAPISpecController()

    @lazy_property
    def management_interface_settings(self):
        return ManagementInterfaceSettingsController()

    @lazy_property
    def mr_l3_firewall(self):
        return MRL3FirewallController()

    @lazy_property
    def mx_l7_firewall(self):
        return MXL7FirewallController()

    @lazy_property
    def group_policies(self):
        return GroupPoliciesController()

    @lazy_property
    def networks(self):
        return NetworksController()

    @lazy_property
    def mv_sense(self):
        return MVSenseController()

    @lazy_property
    def vlans(self):
        return VlansController()

    @lazy_property
    def uplink_settings(self):
        return UplinkSettingsController()

    @lazy_property
    def static_routes(self):
        return StaticRoutesController()

    @lazy_property
    def mx_port_forwarding_rules(self):
        return MXPortForwardingRulesController()

    @lazy_property
    def mx_1_1_nat_rules(self):
        return MX11NATRulesController()

    @lazy_property
    def content_filtering_rules(self):
        return ContentFilteringRulesController()

    @lazy_property
    def content_filtering_categories(self):
        return ContentFilteringCategoriesController()

    @lazy_property
    def syslog_servers(self):
        return SyslogServersController()

    @lazy_property
    def switch_stacks(self):
        return SwitchStacksController()

    @lazy_property
    def switch_profiles(self):
        return SwitchProfilesController()

    @lazy_property
    def switch_settings(self):
        return SwitchSettingsController()

    @lazy_property
    def snmp_settings(self):
        return SNMPSettingsController()

    @lazy_property
    def malware_settings(self):
        return MalwareSettingsController()

    @lazy_property
    def intrusion_settings(self):
        return IntrusionSettingsController()

    @lazy_property
    def radio_settings(self):
        return RadioSettingsController()

    @lazy_property
    def clients(self):
        return ClientsController()

    @lazy_property
    def api_usage(self):
        return APIUsageController()

    @lazy_property
    def net_flow_settings(self):
        return NetFlowSettingsController()

    @lazy_property
    def meraki_auth_users(self):
        return MerakiAuthUsersController()

    @lazy_property
    def http_servers(self):
        return HTTPServersController()

    @lazy_property
    def mx_vpn_firewall(self):
        return MXVPNFirewallController()

    @lazy_property
    def mx_l7_application_categories(self):
        return MXL7ApplicationCategoriesController()

    @lazy_property
    def mx_l3_firewall(self):
        return MXL3FirewallController()

    @lazy_property
    def mx_cellular_firewall(self):
        return MXCellularFirewallController()

    @lazy_property
    def devices(self):
        return DevicesController()

    @lazy_property
    def config_templates(self):
        return ConfigTemplatesController()

    @lazy_property
    def cameras(self):
        return CamerasController()

    @lazy_property
    def bluetooth_clients(self):
        return BluetoothClientsController()

    @lazy_property
    def security_events(self):
        return SecurityEventsController()

    @lazy_property
    def webhook_logs(self):
        return WebhookLogsController()


    def __init__(self,
                 x_cisco_meraki_api_key='15da0c6ffff295f16267f88f98694cf29a86ed87'):
        if x_cisco_meraki_api_key is not None:
            Configuration.x_cisco_meraki_api_key = x_cisco_meraki_api_key

