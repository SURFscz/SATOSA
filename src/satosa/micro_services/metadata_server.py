"""
A metadata server microservice
"""
import os
import logging
from ..micro_services.base import RequestMicroService
from ..response import Response

logger = logging.getLogger(__name__)

class MetadataServer(RequestMicroService):

    logprefix = "METADATA_SERVER_SERVICE:"

    def __init__(self, config, *args, **kwargs):
        """
        :type config: satosa.satosa_config.SATOSAConfig
        :param config: The SATOSA proxy config
        """
        super().__init__(*args, **kwargs)
        #self.config = config
        if 'location' in config:
            self.endpoint = config['location'][0].strip("/")
            self.location = config['location'][1].strip("/")

    def register_endpoints(self):
        logger.info("{} registering {}".format(self.logprefix, self.endpoint))
        return [["^%s/" % self.endpoint, self._handle]]
    
    def _handle(self, context):
        path = context._path.strip(self.endpoint)
        metadata = "%s/%s/%s" % (os.getcwd(), self.location, path)
        logger.info("{} _handle: {}".format(self.logprefix,path))
        try:
            response = open(metadata, 'r').read()
        except:
            response = "Not found"
        return Response(response)

