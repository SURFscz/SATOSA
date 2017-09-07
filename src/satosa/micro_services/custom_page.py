"""
A custom user error microservice
"""
import logging
from ..micro_services.base import RequestMicroService
from ..response import Response

logger = logging.getLogger(__name__)

error_html = '''<h1>Pas Op!</h1>
<p>Foobar %s en daarom altijd je eten opeten!!</p>
'''

info_html = '''<h1>He Hoi!</h1>
<p>Flappie %s en ga zo door!!</p>
'''

class CustomPage(RequestMicroService):

    def __init__(self, config, *args, **kwargs):
        """
        :type config: satosa.satosa_config.SATOSAConfig
        :param config: The SATOSA proxy config
        """
        super().__init__(*args, **kwargs)

    def register_endpoints(self):
        logger.info("CustomPage register_endpoints")
        map = []
        map.append(["^error$", self._handle_error])
        map.append(["^info$", self._handle_info])
        return map
    
    def _handle_error(self, context):
        logger.info("CustomPage _handle_error")
        return Response(error_html % "flappie", "400 Oops")

    def _handle_info(self, context):
        logger.info("CustomPage _handle_info")
        return Response(info_html % "foobar", "200 Mooi zo")

