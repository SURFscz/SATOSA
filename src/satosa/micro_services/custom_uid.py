from .base import ResponseMicroService
from satosa.logging_util import satosa_logging

from xml.etree import ElementTree as ET
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

        name_id = data.name_id
        satosa_logging(logger, logging.DEBUG, "{} Using name_id format {}".format(self.logprefix, name_id.format), context.state)
        satosa_logging(logger, logging.DEBUG, "{} Using name_id text {}".format(self.logprefix, name_id.text), context.state)

        # Obtain configuration details from the per-SP configuration or the default configuration
        try:
            if 'select' in config:
                select = config['select']
            else:
                select = self.config['select']

            if 'custom_attribute' in config:
                custom_attribute = config['custom_attribute']
            else:
                custom_attribute = self.config['custom_attribute']

            if 'user_id' in config:
                user_id = config['user_id']
            else:
                user_id = self.config['user_id']

        except KeyError as err:
            satosa_logging(logger, logging.ERROR, "{} Configuration '{}' is missing".format(self.logprefix, err), context.state)
            return super().process(context, data)

        satosa_logging(logger, logging.DEBUG, "{} select {}".format(self.logprefix, select), context.state)

        d = { a: [] for a in select if a in data.attributes }
        for a in d:
            values = data.attributes.get(a)
            for v in values:
                try:
                    v = ET.fromstring(v).text
                except:
                    pass
                if v:
                    d[a].append(v)

        # Do the magic
        uid = '|'.join(['|'.join(d[a]) for a in select if a in d and len(d[a])])
        satosa_logging(logger, logging.DEBUG, "{} uid: {}".format(self.logprefix, uid), context.state)

        if uid:
            data.attributes[custom_attribute] = [uid]
            if user_id:
                data.user_id = uid
                context.state['IDHASHER']['hash_type'] = 'persistent'

        satosa_logging(logger, logging.DEBUG, "{} custom uid ({}): {}".format(self.logprefix, custom_attribute, data.attributes.get(custom_attribute)), context.state)
        return super().process(context, data)
