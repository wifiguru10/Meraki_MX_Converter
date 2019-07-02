# -*- coding: utf-8 -*-

"""
    meraki

    This file was automatically generated for meraki by APIMATIC v2.0 ( https://apimatic.io ).
"""


class Network2Model(object):

    """Implementation of the 'Network2' model.

    TODO: type model description here.

    Attributes:
        id (string): The network ID
        access (string): The privilege of the SAML administrator on the
            network

    """

    # Create a mapping from Model property names to API property names
    _names = {
        "id":'id',
        "access":'access'
    }

    def __init__(self,
                 id=None,
                 access=None):
        """Constructor for the Network2Model class"""

        # Initialize members of the class
        self.id = id
        self.access = access


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
        id = dictionary.get('id')
        access = dictionary.get('access')

        # Return an object of this model
        return cls(id,
                   access)


