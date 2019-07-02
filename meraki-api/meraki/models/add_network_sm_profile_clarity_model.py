# -*- coding: utf-8 -*-

"""
    meraki

    This file was automatically generated for meraki by APIMATIC v2.0 ( https://apimatic.io ).
"""


class AddNetworkSmProfileClarityModel(object):

    """Implementation of the 'addNetworkSmProfileClarity' model.

    TODO: type model description here.

    Attributes:
        plugin_bundle_id (string): The bundle ID of the application, defaults
            to com.cisco.ciscosecurity.app
        filter_browsers (string): Whether or not to enable browser traffic
            filtering (one of true, false).
        filter_sockets (string): Whether or not to enable socket traffic
            filtering (one of true, false).
        vendor_config (string): The specific VendorConfig to be passed to the
            filtering framework, as JSON. VendorConfig should be an array of
            objects, as: [ { "key": "some_key", type: "some_type", "value":
            "some_value" }, ... ]  type is one of manual_string, manual_int,
            manual_boolean, manual_choice, manual_multiselect, manual_list,
            auto_username, auto_email, auto_mac_address, auto_serial_number,
            auto_notes, auto_name

    """

    # Create a mapping from Model property names to API property names
    _names = {
        "plugin_bundle_id":'PluginBundleID',
        "filter_browsers":'FilterBrowsers',
        "filter_sockets":'FilterSockets',
        "vendor_config":'VendorConfig'
    }

    def __init__(self,
                 plugin_bundle_id=None,
                 filter_browsers=None,
                 filter_sockets=None,
                 vendor_config=None):
        """Constructor for the AddNetworkSmProfileClarityModel class"""

        # Initialize members of the class
        self.plugin_bundle_id = plugin_bundle_id
        self.filter_browsers = filter_browsers
        self.filter_sockets = filter_sockets
        self.vendor_config = vendor_config


    @classmethod
    def from_dictionary(cls,
                        dictionary):
        """Creates an instance of this model from a dictionary

        Args:
            dictionary (dictionary): A dictionary representation of the object as
            obtained from the deserialization of the server's response. The keys
            MUST match property names in the API description.

        Returns:
            object: An instance of this structure class.

        """
        if dictionary is None:
            return None

        # Extract variables from the dictionary
        plugin_bundle_id = dictionary.get('PluginBundleID')
        filter_browsers = dictionary.get('FilterBrowsers')
        filter_sockets = dictionary.get('FilterSockets')
        vendor_config = dictionary.get('VendorConfig')

        # Return an object of this model
        return cls(plugin_bundle_id,
                   filter_browsers,
                   filter_sockets,
                   vendor_config)


