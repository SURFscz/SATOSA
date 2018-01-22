from .base import ResponseMicroService
from satosa.logging_util import satosa_logging

import logging
import hashlib

logger = logging.getLogger(__name__)

class CustomUID(ResponseMicroService):
    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config
        self.logprefix = "CUSTOM_UID:"

    def process(self, context, data):
        # Initialize the configuration to use as the default configuration
        # that is passed during initialization.
        config = self.config

        satosa_logging(logger, logging.DEBUG, "{} Using default configuration {}".format(self.logprefix, config), context.state)

        # Obtain configuration details from the per-SP configuration or the default configuration
        try:
            if 'select' in config:
                select = config['select']
            else:
                select = self.config['select']

            if 'couid' in config:
                couid = config['couid']
            else:
                couid = self.config['couid']

        except KeyError as err:
            satosa_logging(logger, logging.ERROR, "{} Configuration '{}' is missing".format(logprefix, err), context.state)
            return super().process(context, data)

        satosa_logging(logger, logging.DEBUG, "{} select {}".format(self.logprefix, select), context.state)

        # Do the magic
        uid = '|'.join(['|'.join(data.attributes[v]) for v in select if v in data.attributes])
        satosa_logging(logger, logging.DEBUG, "{} uid: {}".format(self.logprefix, uid), context.state)

        if uid:
            data.attributes[couid] = hashlib.sha1(uid.encode('utf-8')).hexdigest()

        satosa_logging(logger, logging.DEBUG, "{} couid ({}): {}".format(self.logprefix, couid, data.attributes.get(couid)), context.state)
        return super().process(context, data)
