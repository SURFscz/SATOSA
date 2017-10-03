"""
SATOSA microservice that uses an identifier asserted by
the home organization SAML IdP as a key to search a DB
for records and then determines access to the
requesting SP.
"""

from .base import ResponseMicroService
from satosa.logging_util import satosa_logging
from ..response import Redirect
from base64 import urlsafe_b64encode, urlsafe_b64decode

import copy
import logging
import MySQLdb

logger = logging.getLogger(__name__)

class DBAcl(ResponseMicroService):
    """
    Use identifier provided by the backend authentication service
    to lookup a person record in DB and obtain attributes
    to assert about the user to the frontend receiving service.
    """
    PEOPLE_TABLE = "zone_people"
    PERSON_SERVICES_TABLE = "zone_person_zone_service"
    SERVICES_TABLE = "zone_services"

    logprefix = "DB_ACL:"

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config

    def process(self, context, data):
        logprefix = DBAcl.logprefix

        # Initialize the configuration to use as the default configuration
        # that is passed during initialization.
        config = self.config
        configClean = copy.deepcopy(config)
        if 'db_password' in configClean:
            configClean['db_password'] = 'XXXXXXXX'

        satosa_logging(logger, logging.DEBUG, "{} Using default configuration {}".format(logprefix, configClean), context.state)

        # Find the entityID for the SP that initiated the flow and target IdP
        try:
            spEntityID = context.state.state_dict['SATOSA_BASE']['requester']
            idpEntityID = data.auth_info.issuer
        except KeyError as err:
            satosa_logging(logger, logging.ERROR, "{} Unable to determine the entityID's for the IdP or SP".format(logprefix), context.state)
            return super().process(context, data)

        satosa_logging(logger, logging.DEBUG, "{} entityID for the requester is {}".format(logprefix, spEntityID), context.state)
        satosa_logging(logger, logging.ERROR, "{} entityID for the source IdP is {}".format(logprefix, idpEntityID), context.state)

        # Examine our configuration to determine if there is a per-SP configuration
        if spEntityID in self.config:
            config = self.config[spEntityID]
            configClean = copy.deepcopy(config)
            if 'db_password' in configClean:
                configClean['db_password'] = 'XXXXXXXX'
            satosa_logging(logger, logging.DEBUG, "{} For SP {} using configuration {}".format(logprefix, spEntityID, configClean), context.state)

        # Obtain configuration details from the per-SP configuration or the default configuration
        try:
            if 'db_host' in config:
                db_host = config['db_host']
            else:
                db_host = self.config['db_host']

            if 'db_user' in config:
                db_user = config['db_user']
            else:
                db_user = self.config['db_user']

            if 'db_schema' in config:
                db_schema = config['db_schema']
            else:
                db_schema = self.config['db_schema']

            if 'db_password' in config:
                db_password = config['db_password']
            else:
                db_password = self.config['db_password']

            if 'idp_identifiers' in config:
                idp_identifiers = config['idp_identifiers']
            else:
                idp_identifiers = self.config['idp_identifiers']

            if 'access_denied' in config:
                access_denied = config['access_denied']
            else:
                access_denied = self.config['access_denied']

        except KeyError as err:
            satosa_logging(logger, logging.ERROR, "{} Configuration '{}' is missing".format(logprefix, err), context.state)
            return super().process(context, data)

        record = None

        try:
            #satosa_logging(logger, logging.DEBUG, "{} Using DB host {}".format(logprefix, db_host), context.state)
            #satosa_logging(logger, logging.DEBUG, "{} Using DB user {}".format(logprefix, db_user), context.state)
            #satosa_logging(logger, logging.DEBUG, "{} Using DB schema {}".format(logprefix, db_schema), context.state)

            connection = MySQLdb.connect(host=db_host, user=db_user, passwd=db_password, db=db_schema)
            cursor = connection.cursor()

            satosa_logging(logger, logging.DEBUG, "{} Connected to DB server".format(logprefix), context.state)
            satosa_logging(logger, logging.DEBUG, "{} Using IdP asserted attributes {}".format(logprefix, idp_identifiers), context.state)

            values = []
            for identifier in idp_identifiers:
                if identifier in data.attributes:
                    satosa_logging(logger, logging.DEBUG, "{} IdP asserted {} values for attribute {}: {}".format(logprefix, len(data.attributes[identifier]),identifier, data.attributes[identifier]), context.state)
                    values += data.attributes[identifier]
                else:
                    satosa_logging(logger, logging.DEBUG, "{} IdP did not assert attribute {}".format(logprefix, identifier), context.state)

            satosa_logging(logger, logging.DEBUG, "{} IdP asserted values for DB id: {}".format(logprefix, values), context.state)

            # Prepare select statement
            query  = "SELECT z.`metadata` FROM `{}` p "
            query += "JOIN `{}` ps ON p.`id`=ps.`zone_person_id` "
            query += "JOIN `{}` z ON ps.`zone_service_id`=z.`id` "
            query += "WHERE p.`uid` in (" + ",".join(['%s']*len(values)) + ") "
            query += "AND z.`metadata`=%s"
            query = query.format(self.PEOPLE_TABLE, self.PERSON_SERVICES_TABLE, self.SERVICES_TABLE)

            satosa_logging(logger, logging.DEBUG, "{} query: {}".format(logprefix, query), context.state)

            # Execute prepared statement
            cursor.execute(query, values + [spEntityID] )

            services = []
            for row in cursor.fetchall():
                satosa_logging(logger, logging.DEBUG, "{} row: {}".format(logprefix, row), context.state)
                services += [row[0]]

            satosa_logging(logger, logging.DEBUG, "{} services: {}".format(logprefix, services), context.state)

        except Exception as err:
            satosa_logging(logger, logging.ERROR, "{} Caught exception: {0}".format(logprefix, err), None)
            return super().process(context, data)

        else:
            satosa_logging(logger, logging.DEBUG, "{} Closing connection to DB server".format(logprefix), context.state)
            connection.close()

        if spEntityID in services:
            satosa_logging(logger, logging.DEBUG, "{} spEntityID found, user may continue".format(logprefix), context.state)
        else:
            satosa_logging(logger, logging.DEBUG, "{} spEntityID not found, user is not allowed".format(logprefix), context.state)
            return Redirect(access_denied)

        return super().process(context, data)
