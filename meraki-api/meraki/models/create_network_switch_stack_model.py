# -*- coding: utf-8 -*-

"""
    meraki

    This file was automatically generated for meraki by APIMATIC v2.0 ( https://apimatic.io ).
"""


class CreateNetworkSwitchStackModel(object):

    """Implementation of the 'createNetworkSwitchStack' model.

    TODO: type model description here.

    Attributes:
        name (string): The name of the new stack
        serials (list of string): An array of switch serials to be added into
            the new stack

    """

    # Create a mapping from Model property names to API property names
    _names = {
        "name":'name',
        "serials":'serials'
    }

    def __init__(self,
                 name=None,
                 serials=None):
        """Constructor for the CreateNetworkSwitchStackModel class"""

        # Initialize members of the class
        self.name = name
        self.serials = serials


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
        name = dictionary.get('name')
        serials = dictionary.get('serials')

        # Return an object of this model
        return cls(name,
                   serials)


