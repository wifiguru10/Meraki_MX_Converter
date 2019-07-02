# -*- coding: utf-8 -*-

"""
    meraki

    This file was automatically generated for meraki by APIMATIC v2.0 ( https://apimatic.io ).
"""

from meraki.api_helper import APIHelper
from meraki.configuration import Configuration
from meraki.controllers.base_controller import BaseController
from meraki.http.auth.custom_header_auth import CustomHeaderAuth

class AdminsController(BaseController):

    """A Controller to access Endpoints in the meraki API."""


    def delete_organization_admin(self,
                                  options=dict()):
        """Does a DELETE request to /organizations/{organizationId}/admins/{id}.

        Revoke all access for a dashboard administrator within this
        organization

        Args:
            options (dict, optional): Key-value pairs for any of the
                parameters to this API Endpoint. All parameters to the
                endpoint are supplied through the dictionary with their names
                being the key and their desired values being the value. A list
                of parameters that can be used are::

                    organization_id -- string -- TODO: type description here.
                        Example: 
                    id -- string -- TODO: type description here. Example: 

        Returns:
            void: Response from the API. Successful operation

        Raises:
            APIException: When an error occurs while fetching the data from
                the remote API. This exception includes the HTTP Response
                code, an error message, and the HTTP body that was received in
                the request.

        """

        # Validate required parameters
        self.validate_parameters(organization_id=options.get("organization_id"),
                                 id=options.get("id"))

        # Prepare query URL
        _url_path = '/organizations/{organizationId}/admins/{id}'
        _url_path = APIHelper.append_url_with_template_parameters(_url_path, { 
            'organizationId': options.get('organization_id', None),
            'id': options.get('id', None)
        })
        _query_builder = Configuration.base_uri
        _query_builder += _url_path
        _query_url = APIHelper.clean_url(_query_builder)

        # Prepare and execute request
        _request = self.http_client.delete(_query_url)
        CustomHeaderAuth.apply(_request)
        _context = self.execute_request(_request)
        self.validate_response(_context)

    def create_organization_admin(self,
                                  options=dict()):
        """Does a POST request to /organizations/{organizationId}/admins.

        Create a new dashboard administrator

        Args:
            options (dict, optional): Key-value pairs for any of the
                parameters to this API Endpoint. All parameters to the
                endpoint are supplied through the dictionary with their names
                being the key and their desired values being the value. A list
                of parameters that can be used are::

                    organization_id -- string -- TODO: type description here.
                        Example: 
                    create_organization_admin -- CreateOrganizationAdminModel
                        -- TODO: type description here. Example: 

        Returns:
            mixed: Response from the API. Successful operation

        Raises:
            APIException: When an error occurs while fetching the data from
                the remote API. This exception includes the HTTP Response
                code, an error message, and the HTTP body that was received in
                the request.

        """

        # Validate required parameters
        self.validate_parameters(organization_id=options.get("organization_id"),
                                 create_organization_admin=options.get("create_organization_admin"))

        # Prepare query URL
        _url_path = '/organizations/{organizationId}/admins'
        _url_path = APIHelper.append_url_with_template_parameters(_url_path, { 
            'organizationId': options.get('organization_id', None)
        })
        _query_builder = Configuration.base_uri
        _query_builder += _url_path
        _query_url = APIHelper.clean_url(_query_builder)

        # Prepare headers
        _headers = {
            'accept': 'application/json',
            'content-type': 'application/json; charset=utf-8'
        }

        # Prepare and execute request
        _request = self.http_client.post(_query_url, headers=_headers, parameters=APIHelper.json_serialize(options.get('create_organization_admin')))
        CustomHeaderAuth.apply(_request)
        _context = self.execute_request(_request)
        self.validate_response(_context)

        # Return appropriate type
        return APIHelper.json_deserialize(_context.response.raw_body)

    def get_organization_admins(self,
                                organization_id):
        """Does a GET request to /organizations/{organizationId}/admins.

        List the dashboard administrators in this organization

        Args:
            organization_id (string): TODO: type description here. Example: 

        Returns:
            mixed: Response from the API. Successful operation

        Raises:
            APIException: When an error occurs while fetching the data from
                the remote API. This exception includes the HTTP Response
                code, an error message, and the HTTP body that was received in
                the request.

        """

        # Validate required parameters
        self.validate_parameters(organization_id=organization_id)

        # Prepare query URL
        _url_path = '/organizations/{organizationId}/admins'
        _url_path = APIHelper.append_url_with_template_parameters(_url_path, { 
            'organizationId': organization_id
        })
        _query_builder = Configuration.base_uri
        _query_builder += _url_path
        _query_url = APIHelper.clean_url(_query_builder)

        # Prepare headers
        _headers = {
            'accept': 'application/json'
        }

        # Prepare and execute request
        _request = self.http_client.get(_query_url, headers=_headers)
        CustomHeaderAuth.apply(_request)
        _context = self.execute_request(_request)
        self.validate_response(_context)

        # Return appropriate type
        return APIHelper.json_deserialize(_context.response.raw_body)

    def update_organization_admin(self,
                                  options=dict()):
        """Does a PUT request to /organizations/{organizationId}/admins/{id}.

        Update an administrator

        Args:
            options (dict, optional): Key-value pairs for any of the
                parameters to this API Endpoint. All parameters to the
                endpoint are supplied through the dictionary with their names
                being the key and their desired values being the value. A list
                of parameters that can be used are::

                    organization_id -- string -- TODO: type description here.
                        Example: 
                    id -- string -- TODO: type description here. Example: 
                    update_organization_admin -- UpdateOrganizationAdminModel
                        -- TODO: type description here. Example: 

        Returns:
            mixed: Response from the API. Successful operation

        Raises:
            APIException: When an error occurs while fetching the data from
                the remote API. This exception includes the HTTP Response
                code, an error message, and the HTTP body that was received in
                the request.

        """

        # Validate required parameters
        self.validate_parameters(organization_id=options.get("organization_id"),
                                 id=options.get("id"))

        # Prepare query URL
        _url_path = '/organizations/{organizationId}/admins/{id}'
        _url_path = APIHelper.append_url_with_template_parameters(_url_path, { 
            'organizationId': options.get('organization_id', None),
            'id': options.get('id', None)
        })
        _query_builder = Configuration.base_uri
        _query_builder += _url_path
        _query_url = APIHelper.clean_url(_query_builder)

        # Prepare headers
        _headers = {
            'accept': 'application/json',
            'content-type': 'application/json; charset=utf-8'
        }

        # Prepare and execute request
        _request = self.http_client.put(_query_url, headers=_headers, parameters=APIHelper.json_serialize(options.get('update_organization_admin')))
        CustomHeaderAuth.apply(_request)
        _context = self.execute_request(_request)
        self.validate_response(_context)

        # Return appropriate type
        return APIHelper.json_deserialize(_context.response.raw_body)
