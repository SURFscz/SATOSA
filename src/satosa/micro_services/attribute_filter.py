import re

from .base import ResponseMicroService
from satosa.logging_util import satosa_logging
from ..util import get_dict_defaults

import logging

logger = logging.getLogger(__name__)

class AttributeFilter(ResponseMicroService):
    """
A microservice that performs regexp-based filtering based on response
attributes. The configuration assumes a dict with two keys: attributes_allow
and attributes_deny. An examples speaks volumes:

```yaml
config:
    attribute_deny:
        default:
            default:
                "^eppn":
                   - "^[^@]+$"
    attribute_allow:
        target_provider1:
            requester1:
                "attr1$":
                   - "^foo:bar$"
                   - "^kaka"
            default:
                "attr1$":
                   - "plupp@.+$"
        "":
            "":
                "^attr2":
                   - "^knytte:.*$"

```

The use of "" and 'default' is synonymous. Attribute rules are not overloaded
or inherited. For instance a response from "provider2" would only be allowed
through if the eppn attribute had all values containing an '@' (something
perhaps best implemented via an allow rule in practice). Responses from
target_provider1 bound for requester1 would be allowed through only if
attributes ending on attr1 contained exactly foo:bar or started with kaka.
Note that attribute filters work on matched value only.
 - i.e both attribute name and value need to match.
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.attribute_allow = config.get("attribute_allow", {})
        self.attribute_deny = config.get("attribute_deny", {})
        self.logprefix = "ATTR_FILTER:"

    def _filter_attributes(self, attributes, filters):
        attributes_filter = {}
        for f,fv in filters.items():
            for a in attributes.keys():
                if re.compile(f).search(a):
                    attributes_filter.setdefault(a,[]).extend(fv)
        attributes_filtered = { a: list(filter(re.compile("|".join(f)).search, attributes.get(a, None))) for a, f in attributes_filter.items() }
        return attributes_filtered

    def _apply_filter(self, context, attributes, provider, requester):
        filter_allow = get_dict_defaults(self.attribute_allow, provider, requester)
        satosa_logging(logger, logging.DEBUG, "{} filter_allow: {}".format(self.logprefix, filter_allow), context.state)
        filter_deny  = get_dict_defaults(self.attribute_deny, provider, requester)
        satosa_logging(logger, logging.DEBUG, "{} filter_deny: {}".format(self.logprefix, filter_deny), context.state)
        allow = self._filter_attributes(attributes, filter_allow)
        satosa_logging(logger, logging.DEBUG, "{} allow: {}".format(self.logprefix, allow), context.state)
        deny  = self._filter_attributes(attributes, filter_deny)
        satosa_logging(logger, logging.DEBUG, "{} deny: {}".format(self.logprefix, deny), context.state)

        # Remove Denies (values) from Allows (values)
        for a,v in deny.items():
            for r in v:
                if a in allow and r in allow[a]:
                    allow[a].remove(r)

        result = { a: v for a, v in allow.items() if len(v) }
        satosa_logging(logger, logging.DEBUG, "{} result: {}".format(self.logprefix, result), context.state)
        return result

    def process(self, context, data):
        satosa_logging(logger, logging.DEBUG, "{} Processing attribute filter".format(self.logprefix), context.state)
        data.attributes = self._apply_filter(context, data.attributes, data.auth_info.issuer, data.requester)
        return super().process(context, data)
