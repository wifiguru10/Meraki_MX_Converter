# -*- coding: utf-8 -*-

"""
    meraki

    This file was automatically generated for meraki by APIMATIC v2.0 ( https://apimatic.io ).
"""


class ThursdayModel(object):

    """Implementation of the 'Thursday' model.

    The schedule object for Thursday.

    Attributes:
        active (bool): Whether the schedule is active (true) or inactive
            (false) during the time specified between 'from' and 'to'.
            Defaults to true.
        mfrom (string): The time, from '00:00' to '24:00'. Must be less than
            the time specified in 'to'. Defaults to '00:00'. Only 30 minute
            increments are allowed.
        to (string): The time, from '00:00' to '24:00'. Must be greater than
            the time specified in 'from'. Defaults to '24:00'. Only 30 minute
            increments are allowed.

    """

    # Create a mapping from Model property names to API property names
    _names = {
        "active":'active',
        "mfrom":'from',
        "to":'to'
    }

    def __init__(self,
                 active=None,
                 mfrom=None,
                 to=None):
        """Constructor for the ThursdayModel class"""

        # Initialize members of the class
        self.active = active
        self.mfrom = mfrom
        self.to = to


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
        active = dictionary.get('active')
        mfrom = dictionary.get('from')
        to = dictionary.get('to')

        # Return an object of this model
        return cls(active,
                   mfrom,
                   to)


