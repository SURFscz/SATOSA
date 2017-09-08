"""
A custom user error microservice
"""
import logging
from ..micro_services.base import RequestMicroService
from ..response import Response

logger = logging.getLogger(__name__)

class CustomPage(RequestMicroService):

    logprefix = "CUSTOM_PAGE_SERVICE:"

    def __init__(self, config, *args, **kwargs):
        """
        :type config: satosa.satosa_config.SATOSAConfig
        :param config: The SATOSA proxy config
        """
        super().__init__(*args, **kwargs)
        #self.config = config
        if 'pages' in config:
            self.pages = config['pages']

    def register_endpoints(self):
        url_map = []
        for page in self.pages:
            url_map.append(["^%s$" % page, self._handle])
        return url_map
    
    def _handle(self, context):
        page = context._path
        logger.info("{} _handle: {}".format(self.logprefix, page))
        return Response(self.pages[page])

