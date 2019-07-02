# -*- coding: utf-8 -*-

"""
    meraki

    This file was automatically generated for meraki by APIMATIC v2.0 ( https://apimatic.io ).
"""

import meraki.models.rule_model

class UpdateNetworkL3FirewallRulesModel(object):

    """Implementation of the 'updateNetworkL3FirewallRules' model.

    TODO: type model description here.

    Attributes:
        rules (list of RuleModel): An ordered array of the firewall rules (not
            including the default rule)
        syslog_default_rule (bool): Log the special default rule (boolean
            value - enable only if you've configured a syslog server)
            (optional)

    """

    # Create a mapping from Model property names to API property names
    _names = {
        "rules":'rules',
        "syslog_default_rule":'syslogDefaultRule'
    }

    def __init__(self,
                 rules=None,
                 syslog_default_rule=False):
        """Constructor for the UpdateNetworkL3FirewallRulesModel class"""

        # Initialize members of the class
        self.rules = rules
        self.syslog_default_rule = syslog_default_rule
        #self.syslog_default_rule = False


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
        rules = None
        if dictionary.get('rules') != None:
            rules = list()
            for structure in dictionary.get('rules'):
                rules.append(meraki.models.rule_model.RuleModel.from_dictionary(structure))
        syslog_default_rule = dictionary.get('syslogDefaultRule')

        # Return an object of this model
        return cls(rules,
                   syslog_default_rule)


