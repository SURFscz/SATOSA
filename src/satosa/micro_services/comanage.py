"""
SATOSA microservice that inspects Comanage.
"""

from .base import ResponseMicroService
from satosa.logging_util import satosa_logging
from http.client import HTTPSConnection
from base64 import b64encode
from ..response import Response

import requests
import json
import copy
import logging

logger = logging.getLogger(__name__)

class ComanageService(ResponseMicroService):
    """
    Use context and data object to create custom log output
    """
    logprefix = "COMANAGE_SERVICE:"

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config
        
    def process(self, context, data):
        logprefix = ComanageService.logprefix

        # Initialize the configuration to use as the default configuration
        # that is passed during initialization.
        config = self.config
        configClean = copy.deepcopy(config)
        if 'password' in configClean:
            configClean['password'] = 'XXXXXXXX'    

        satosa_logging(logger, logging.DEBUG, "{} Using default configuration {}".format(logprefix, configClean), context.state)

        # Find the entityID for the SP that initiated the flow and target IdP
        try:
            spEntityID = context.state.state_dict['SATOSA_BASE']['requester']
        except KeyError as err:
            satosa_logging(logger, logging.ERROR, "{} Unable to determine the entityID for the SP".format(logprefix), context.state)
            return super().process(context, data)

        satosa_logging(logger, logging.DEBUG, "{} entityID for the SP requester is {}".format(logprefix, spEntityID), context.state)

        # Obtain configuration details from the per-SP configuration or the default configuration
        try:
            if 'comanage_url' in config:
                comanage_url = config['comanage_url']
            else:
                comanage_url = self.config['comanage_url']
            if 'user' in config:
                user = config['user']
            else:
                user = self.config['user']
            if 'password' in config:
                password = config['password']
            else:
                password = self.config['password']

        except KeyError as err:
            satosa_logging(logger, logging.ERROR, "{} Configuration '{}' is missing".format(logprefix, err), context.state)
            return super().process(context, data)

        record = None

        try:
            satosa_logging(logger, logging.DEBUG, "{} Comanage Start".format(logprefix, context), context.state)
            satosa_logging(logger, logging.DEBUG, "{} Using context {}".format(logprefix, context), context.state)
            satosa_logging(logger, logging.DEBUG, "{} Using data {}".format(logprefix, data.to_dict()), context.state)

            services_url = comanage_url + 'registry/co_services.json'
            satosa_logging(logger, logging.DEBUG, "{} services_url {}".format(logprefix, services_url), context.state)
            r = requests.get(services_url, verify=False, auth=(user, password))

            satosa_logging(logger, logging.DEBUG, "{} request.json {}".format(logprefix, r.json()), context.state)

            co_services = r.json()['CoServices']
            satosa_logging(logger, logging.DEBUG, "{} co_services {}".format(logprefix, co_services), context.state)

            services = {}
            for co_service in co_services:
                services[co_service['Name']] = co_service['CoId']

            satosa_logging(logger, logging.DEBUG, "{} services {}".format(logprefix, services), context.state)

            if spEntityID in services:
                co_id = services[spEntityID]
            else:
                return Response("No CO for entityID: {}".format(spEntityID))

            if 'eppn' in data.attributes:
                eppn = data.attributes['eppn'][0]
            else:
                return Response("No eppn found: can't match CO")

            co_people_url = comanage_url + 'registry/co_people.json?coid=' + co_id + '&search.identifier=' + eppn
            satosa_logging(logger, logging.DEBUG, "{} co_people_url {}".format(logprefix, co_people_url), context.state)
            r = requests.get(co_people_url, verify=False, auth=(user, password))
            
            satosa_logging(logger, logging.DEBUG, "{} request.json {}".format(logprefix, r.json()), context.state)

            member = len(r.json()['CoPeople'])
            if (member):
                satosa_logging(logger, logging.DEBUG, "{} {} is member".format(logprefix, eppn), context.state)
            else:
                satosa_logging(logger, logging.DEBUG, "{} {} is no member".format(logprefix, eppn), context.state)
                return Response("eppn {} not member of CO service  {}". format(eppn, spEntityID))

        except Exception as err:
            satosa_logging(logger, logging.ERROR, "{} Caught exception: {0}".format(logprefix, err), None)
            return super().process(context, data)

        else:
            satosa_logging(logger, logging.DEBUG, "{} Comanage Done".format(logprefix), context.state)

        return super().process(context, data)
