"""
SATOSA microservice that checks existance of certain attributes
requesting SP.
"""

from .base import ResponseMicroService
from satosa.logging_util import satosa_logging
from ..response import Redirect

import copy
import logging

logger = logging.getLogger(__name__)

class AttributesAcl(ResponseMicroService):
    """
    Use identifier provided by the backend authentication service
    to lookup a person record in DB and obtain attributes
    to assert about the user to the frontend receiving service.
    """
    logprefix = "ATTRIBUTES_ACL:"

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config

    def process(self, context, data):
        logprefix = AttributesAcl.logprefix

        # Initialize the configuration to use as the default configuration
        # that is passed during initialization.
        config = self.config
        configClean = copy.deepcopy(config)

        satosa_logging(logger, logging.DEBUG, "{} Using default configuration {}".format(logprefix, configClean), context.state)

        # Obtain configuration details from the per-SP configuration or the default configuration
        try:
            if 'required_attributes' in config:
                required_attributes = config['required_attributes']
            else:
                required_attributes = self.config['required_attributes']

            if 'access_denied' in config:
                access_denied = config['access_denied']
            else:
                access_denied = self.config['access_denied']

        except KeyError as err:
            satosa_logging(logger, logging.ERROR, "{} Configuration '{}' is missing".format(logprefix, err), context.state)
            return super().process(context, data)

        received_attributes = data.attributes.keys()

        satosa_logging(logger, logging.DEBUG, "{} attributes received: {}".format(logprefix, received_attributes), context.state)
        satosa_logging(logger, logging.DEBUG, "{} attributes required: {}".format(logprefix, required_attributes), context.state)

        # Do the hard work
        if set(required_attributes) <= set(received_attributes):
            satosa_logging(logger, logging.DEBUG, "{} required attributes found, user may continue".format(logprefix), context.state)
        else:
            satosa_logging(logger, logging.DEBUG, "{} missing required attributes, user may not continue".format(logprefix), context.state)
            return Redirect(access_denied)

        return super().process(context, data)
