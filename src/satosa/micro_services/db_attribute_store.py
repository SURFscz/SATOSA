"""
SATOSA microservice that uses an identifier asserted by 
the home organization SAML IdP as a key to search a DB
for records and then consume attributes from
the record and assert them to the receiving SP.
"""

from .base import ResponseMicroService
from satosa.logging_util import satosa_logging
from base64 import urlsafe_b64encode, urlsafe_b64decode

import copy
import logging
import sqlite3

logger = logging.getLogger(__name__)

class DBAttributeStore(ResponseMicroService):
    """
    Use identifier provided by the backend authentication service
    to lookup a person record in DB and obtain attributes
    to assert about the user to the frontend receiving service.
    """
    logprefix = "DB_ATTRIBUTE_STORE:"

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config

    def process(self, context, data):
        logprefix = DBAttributeStore.logprefix

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
            router = context.state.state_dict['ROUTER']
            idpEntityID = urlsafe_b64decode(context.state.state_dict[router]['target_entity_id']).decode("utf-8")
        except KeyError as err:
            satosa_logging(logger, logging.ERROR, "{} Unable to determine the entityID's for the IdP or SP".format(logprefix), context.state)
            return super().process(context, data)

        satosa_logging(logger, logging.DEBUG, "{} entityID for the SP requester is {}".format(logprefix, spEntityID), context.state)
        satosa_logging(logger, logging.ERROR, "{} entityID for the target IdP is {}".format(logprefix, idpEntityID), context.state)

        # Examine our configuration to determine if there is a per-SP configuration
        if spEntityID in self.config:
            config = self.config[spEntityID]
            configClean = copy.deepcopy(config)
            if 'db_password' in configClean:
                configClean['db_password'] = 'XXXXXXXX'    
            satosa_logging(logger, logging.DEBUG, "{} For SP {} using configuration {}".format(logprefix, spEntityID, configClean), context.state)
        
        # Obtain configuration details from the per-SP configuration or the default configuration
        try:
            if 'db_url' in config:
                db_url = config['db_url']
            else:
                db_url = self.config['db_url']

            if 'db_user' in config:
                db_user = config['db_user']
            else:
                db_user = self.config['db_user']

            if 'db_table' in config:
                db_table = config['db_table']
            else:
                db_table = self.config['db_table']

            if 'db_password' in config:
                db_password = config['db_password']
            else:
                db_password = self.config['db_password']

            if 'search_return_attributes' in config:
                search_return_attributes = config['search_return_attributes']
            else:
                search_return_attributes = self.config['search_return_attributes']

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
            satosa_logging(logger, logging.DEBUG, "{} Using DB URL {}".format(logprefix, db_url), context.state)
            #server = sqlite3.Server(db_url)
            satosa_logging(logger, logging.DEBUG, "{} Using DB user {}".format(logprefix, db_user), context.state)
            connection = sqlite3.connect(db_url)
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
    
            return_attributes = list(search_return_attributes.keys())
            satosa_logging(logger, logging.DEBUG, "{} DB requested attributes: {}".format(logprefix, return_attributes), context.state)

            satosa_logging(logger, logging.DEBUG, "{} ValuesIdP asserted values for DB id: {}".format(logprefix, values), context.state)
    
            query  = "select `attribute`, `value` from `%s` where "
            query += "attribute in (" + "','".join("?"*len(return_attributes)) + ") and "
            query += "idp=? and sp=? and id in (" + ",".join("?"*len(values)) + ")"
            query %= db_table

            satosa_logging(logger, logging.DEBUG, "{} query: {}".format(logprefix, query), context.state)

            return_values = {}
            for row in cursor.execute(query, return_attributes + [idpEntityID] + [spEntityID] + values):
                satosa_logging(logger, logging.DEBUG, "{} row: {}".format(logprefix, row), context.state)
                if (not return_values.get(search_return_attributes[row[0]])):
                    return_values[search_return_attributes[row[0]]] = []
                return_values[search_return_attributes[row[0]]].append(row[1])

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
            satosa_logging(logger, logging.DEBUG, "{} Clearing values for these input attributes: {}".format(logprefix, data.attributes), context.state)
            data.attributes = {}

        data.attributes.update(return_values)

        satosa_logging(logger, logging.DEBUG, "{} returning data.attributes {}".format(logprefix, str(data.attributes)), context.state)
        return super().process(context, data)
