"""
SATOSA microservice that checks whether user attributes
have changed since last visit
"""

from .base import ResponseMicroService
from satosa.logging_util import satosa_logging
from base64 import b64encode, urlsafe_b64encode, urlsafe_b64decode
from ..attribute_mapping import AttributeMapper
from ..response import Redirect
from hashlib import sha256

import json
import copy
import logging
import MySQLdb

logger = logging.getLogger(__name__)

class AttributeCheck(ResponseMicroService):
    """
    ... some explanation
    """
    ATTRIBUTEHASH_TABLE = "attributes_hash"

    logprefix = "ATTRIBUTE_CHECK:"

    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config
        self.converter = AttributeMapper(internal_attributes)

    def process(self, context, data):
        logprefix = self.logprefix

        # Initialize the configuration to use as the default configuration
        # that is passed during initialization.
        config = self.config
        configClean = copy.deepcopy(config)
        if 'db_password' in configClean:
            configClean['db_password'] = 'XXXXXXXX'

        #satosa_logging(logger, logging.DEBUG, "{} Using default configuration {}".format(logprefix, configClean), context.state)

        # Find the entityID for the SP that initiated the flow and target IdP
        try:
            spEntityID = context.state.state_dict['SATOSA_BASE']['requester']
            idpEntityID = data.auth_info.issuer
        except KeyError as err:
            satosa_logging(logger, logging.ERROR, "{} Unable to determine the entityID's for the IdP or SP".format(logprefix), context.state)
            return super().process(context, data)

        #satosa_logging(logger, logging.DEBUG, "{} entityID for the requester is {}".format(logprefix, spEntityID), context.state)
        #satosa_logging(logger, logging.ERROR, "{} entityID for the source IdP is {}".format(logprefix, idpEntityID), context.state)

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

            if 'changed' in config:
                changed = config['changed']
            else:
                changed = self.config['changed']

        except KeyError as err:
            satosa_logging(logger, logging.ERROR, "{} Configuration '{}' is missing".format(logprefix, err), context.state)
            return super().process(context, data)

        try:
            #satosa_logging(logger, logging.DEBUG, "{} Using DB host {}".format(logprefix, db_host), context.state)
            #satosa_logging(logger, logging.DEBUG, "{} Using DB user {}".format(logprefix, db_user), context.state)
            #satosa_logging(logger, logging.DEBUG, "{} Using DB schema {}".format(logprefix, db_schema), context.state)

            satosa_logging(logger, logging.DEBUG, "{} Using user_id {}".format(logprefix, data.user_id), context.state)

            attributes = data.to_dict()['attr']
            satosa_logging(logger, logging.DEBUG, "{} Using attributes {}".format(logprefix, attributes), context.state)

            def make_hashable(o):
                if isinstance(o, (tuple, list)):
                    return tuple((make_hashable(e) for e in o))
                if isinstance(o, dict):
                    return tuple(sorted((k,make_hashable(v)) for k,v in o.items()))
                if isinstance(o, (set, frozenset)):
                    return tuple(sorted(make_hashable(e) for e in o))
                return o

            def make_hash_sha256(o):
                hasher = sha256()
                hasher.update(repr(make_hashable(o)).encode())
                return b64encode(hasher.digest()).decode()

            #frozen_attributes = freeze(attributes)
            #satosa_logging(logger, logging.DEBUG, "{} Using frozenset {}".format(logprefix, frozen_attributes), context.state)
            attributes_hash = make_hash_sha256(attributes)
            #satosa_logging(logger, logging.DEBUG, "{} Using hashed frozenset {}".format(logprefix, attributes_hash), context.state)

            connection = MySQLdb.connect(host=db_host, user=db_user, passwd=db_password, db=db_schema)
            cursor = connection.cursor()

            #satosa_logging(logger, logging.DEBUG, "{} Connected to DB server".format(logprefix), context.state)

            # Prepare select statement
            query  = "SELECT a.`hash` FROM `{}` a "
            query += "WHERE a.`nameid` = %s"
            query = query.format(self.ATTRIBUTEHASH_TABLE)

            #satosa_logging(logger, logging.DEBUG, "{} query: {}".format(logprefix, query), context.state)

            # Execute prepared statement
            cursor.execute(query, [data.user_id])

            attributes_changed = False

            rows = cursor.fetchall();
            if (not len(rows)):
                #satosa_logging(logger, logging.DEBUG, "{} No rows found, insert hash".format(logprefix), context.state)
                query = "INSERT INTO `{}` (`nameid`, `hash`) VALUES (%s, %s)".format(self.ATTRIBUTEHASH_TABLE)
                #satosa_logging(logger, logging.DEBUG, "{} query: {}".format(logprefix, query), context.state)
                cursor.execute(query, [data.user_id, attributes_hash])
                stored_attributes_hash = attributes_hash
            else:
                stored_attributes_hash = rows[0][0]
                if (attributes_hash != stored_attributes_hash):
                    #satosa_logging(logger, logging.DEBUG, "{} attributes have changed".format(logprefix), context.state)
                    query = "UPDATE `{}` SET `hash`=%s WHERE `nameid`=%s".format(self.ATTRIBUTEHASH_TABLE)
                    #satosa_logging(logger, logging.DEBUG, "{} query: {}".format(logprefix, query), context.state)
                    cursor.execute(query, [attributes_hash, data.user_id])
                    stored_attributes_hash = attributes_hash
                    attributes_changed = True

            satosa_logging(logger, logging.DEBUG, "{} hash: {}, changed: {}".format(logprefix, stored_attributes_hash, attributes_changed), context.state)

        except Exception as err:
            satosa_logging(logger, logging.ERROR, "{} Caught exception: {0}".format(logprefix, err), None)
            return super().process(context, data)

        else:
            #satosa_logging(logger, logging.DEBUG, "{} Closing connection to DB server".format(logprefix), context.state)
            connection.commit()
            connection.close()

        if attributes_changed:
            return Redirect(changed)
        else:
            return super().process(context, data)
