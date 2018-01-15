"""
SATOSA microservice that checks compliance with R&S attribute set
"""

from .base import ResponseMicroService
from satosa.logging_util import satosa_logging
from ..response import Redirect

import copy
import logging

logger = logging.getLogger(__name__)

class RandSAcl(ResponseMicroService):
    """
    Check existance of R&S attributes
    """
    logprefix = "R_AND_S_ACL:"

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config

    def process(self, context, data):
        logprefix = RandSAcl.logprefix

        # Initialize the configuration to use as the default configuration
        # that is passed during initialization.
        config = self.config
        configClean = copy.deepcopy(config)

        satosa_logging(logger, logging.DEBUG, "{} Using default configuration {}".format(logprefix, configClean), context.state)

        # Obtain configuration details from the per-SP configuration or the default configuration
        try:
            if 'attribute_mapping' in config:
                attribute_mapping = config['attribute_mapping']
            else:
                attibute_mapping = self.config['attribute_mapping']
            if 'access_denied' in config:
                access_denied = config['access_denied']
            else:
                access_denied = self.config['access_denied']

        except KeyError as err:
            satosa_logging(logger, logging.ERROR, "{} Configuration '{}' is missing".format(logprefix, err), context.state)
            return super().process(context, data)

        # Show what we have
        satosa_logging(logger, logging.DEBUG, "{} attribute mapping: {}".format(logprefix, attribute_mapping), context.state)

        received_attributes = data.attributes
        satosa_logging(logger, logging.DEBUG, "{} attributes received: {}".format(logprefix, received_attributes), context.state)

        # Do the hard work
        valid_attributes = { a: received_attributes[v] for (a, v) in attribute_mapping.items() if (v in received_attributes and ''.join(received_attributes[v])) }
        satosa_logging(logger, logging.DEBUG, "{} valid attributes: {}".format(logprefix, valid_attributes), context.state)

        isset = { a: a in valid_attributes for a in attribute_mapping.keys() }
        satosa_logging(logger, logging.DEBUG, "{} isset: {}".format(logprefix, isset), context.state)

        valid_r_and_s = (isset['edupersonprincipalname'] or (isset['edupersonprincipalname'] and isset['edupersontargetedid'])) and (isset['displayname'] or (isset['givenname'] and isset['sn'])) and isset['mail']

        if valid_r_and_s:
            satosa_logging(logger, logging.DEBUG, "{} R&S attribute set found, user may continue".format(logprefix), context.state)
        else:
            satosa_logging(logger, logging.DEBUG, "{} missing R&S attribute set, user may not continue".format(logprefix), context.state)
            context.state['substitutions'] = { '%custom%': data.auth_info.issuer }
            return Redirect(access_denied)

        return super().process(context, data)
