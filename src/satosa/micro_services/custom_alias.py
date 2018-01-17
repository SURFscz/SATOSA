"""
A Custom Alias microservice
"""
import os
import logging
from ..micro_services.base import RequestMicroService
from ..response import Response

logger = logging.getLogger(__name__)

class CustomAlias(RequestMicroService):

    logprefix = "CUSTOM_ALIAS_SERVICE:"

    def __init__(self, config, *args, **kwargs):
        """
        :type config: satosa.satosa_config.SATOSAConfig
        :param config: The SATOSA proxy config
        """
        super().__init__(*args, **kwargs)
        #self.config = config
        if 'locations' in config:
            self.locations = config['locations']

    def register_endpoints(self):
        url_map = []
        for endpoint, alias in self.locations.items():
            endpoint = endpoint.strip("/")
            logger.info("{} registering {} - {}".format(self.logprefix, endpoint, alias))
            url_map.append(["^%s/" % endpoint, self._handle])
        return url_map

    def _handle(self, context):
        path = context._path
        endpoint = path.split("/")[0]
        target = path[len(endpoint)+1:]
        alias = "%s/%s/%s" % (os.getcwd(), self.locations[endpoint], target)
        logger.info("{} _handle: {} - {} - {}".format(self.logprefix, endpoint, target, alias))
        try:
            response = open(alias, 'r').read()
        except:
            response = "Not found"

        if 'substitutions' in context.state:
            for search, replace in context.state['substitutions'].items():
                logger.info("search: {}, replace: {}".format(search, replace))
                response = response.replace(search, replace)

        return Response(response)

