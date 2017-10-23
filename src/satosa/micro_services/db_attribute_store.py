"""
SATOSA microservice that uses an identifier asserted by
the home organization SAML IdP as a key to search a DB
for records and then consume attributes from
the record and assert them to the receiving SP.
"""

from .base import ResponseMicroService
from satosa.logging_util import satosa_logging
from base64 import urlsafe_b64encode, urlsafe_b64decode
from ..attribute_mapping import AttributeMapper

import json
import copy
import logging
import MySQLdb

logger = logging.getLogger(__name__)

class DBAttributeStore(ResponseMicroService):
    """
    Use identifier provided by the backend authentication service
    to lookup a person record in DB and obtain attributes
    to assert about the user to the frontend receiving service.
    """
    PEOPLE_TABLE = "zone_people"
    PERSON_SERVICES_TABLE = "zone_person_zone_service"
    SERVICES_TABLE = "zone_services"

    logprefix = "DB_ATTRIBUTE_STORE:"
    attribute_profile = 'saml'

    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config
        self.converter = AttributeMapper(internal_attributes)

    def process(self, context, data):
        logprefix = DBAttributeStore.logprefix
        attribute_profile = DBAttributeStore.attribute_profile

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
            #router = context.state.state_dict['ROUTER']
            #idpEntityID = urlsafe_b64decode(context.state.state_dict[router]['target_entity_id']).decode("utf-8")
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

            if 'clear_input_attributes' in config:
                clear_input_attributes = config['clear_input_attributes']
            elif 'clear_input_attributes' in self.config:
                clear_input_attributes = self.config['clear_input_attributes']
            else:
                clear_input_attributes = False

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

            return_values = {}

            if (len(values) > 0):
                # Prepare select statement
                query  = "SELECT p.`attributes` FROM `{}` p "
                query += "JOIN `{}` ps ON p.`id`=ps.`zone_person_id` "
                query += "JOIN `{}` z ON ps.`zone_service_id`=z.`id` "
                query += "WHERE p.`uid` in (" + ",".join(['%s']*len(values)) + ") "
                query += "AND z.`metadata`=%s"
                query = query.format(self.PEOPLE_TABLE, self.PERSON_SERVICES_TABLE, self.SERVICES_TABLE)

                satosa_logging(logger, logging.DEBUG, "{} query: {}".format(logprefix, query), context.state)

                # Execute prepared statement
                cursor.execute(query, values + [spEntityID] )

                for row in cursor.fetchall():
                    satosa_logging(logger, logging.DEBUG, "{} row: {}".format(logprefix, row), context.state)
                    return_values=json.loads(row[0])

                return_values = self.converter.to_internal(self.attribute_profile, return_values)

            satosa_logging(logger, logging.DEBUG, "{} return_values: {}".format(logprefix, return_values), context.state)

        except Exception as err:
            satosa_logging(logger, logging.ERROR, "{} Caught exception: {0}".format(logprefix, err), None)
            return super().process(context, data)

        else:
            satosa_logging(logger, logging.DEBUG, "{} Closing connection to DB server".format(logprefix), context.state)
            connection.close()

        # Before using a found record, if any, to populate attributes
        # clear any attributes incoming to this microservice if so configured.
        if clear_input_attributes:
            satosa_logging(logger, logging.DEBUG, "{} Clearing values from input attributes".format(logprefix), context.state)

        for k, v in return_values.items():
            if isinstance(v, str):
                v = [v]
            if k in data.attributes and not clear_input_attributes:
                data.attributes[k] = data.attributes[k] + v
            else:
                data.attributes[k] = v

        satosa_logging(logger, logging.DEBUG, "{} returning data.attributes {}".format(logprefix, str(data.attributes)), context.state)
        return super().process(context, data)
