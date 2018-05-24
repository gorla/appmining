# coding=utf-8
""" This file contains some methods used across all Luigi Tasks """

import sys

sys.path.append("..")
from constants import CONTENT_RESOLVER_QUERY_API, CONTENT_RESOLVER_INSERT_API, CONTENT_RESOLVER_UPDATE_API, \
    CONTENT_RESOLVER_CAT, CONTENT_RESOLVER_READ_PERM_MAPPING, CONTENT_RESOLVER_WRITE_PERM_MAPPING


# returns true if an api is a ContentResolver APi
def is_cr_api(api):
    return api.endswith('}')


# returns the set of permissions that are required by the content
# resolver categories
def get_perm_from_api_categories(api):
    base_api = api[:api.index('>') + 1]
    cat_string = api[api.index('{') + 1:api.index('}')]

    # return empty list if the categories string is empty
    if len(cat_string) == 0:
        return []

    # get categories from categories string
    categories = [c.strip() for c in cat_string.split(',')]

    req_perms = set()
    for cat in categories:
        # extract the base category
        base_cat = CONTENT_RESOLVER_CAT[cat]

        # we have to differenciate between read and write permission
        # according to which api is called (query vs insert/update)
        # if the api is query it's a read permission
        if base_api in CONTENT_RESOLVER_QUERY_API:

            # if the base category matches one in the mapping,
            # add the relative permissions to the return set
            if base_cat in CONTENT_RESOLVER_READ_PERM_MAPPING:
                perms = CONTENT_RESOLVER_READ_PERM_MAPPING[base_cat]
                req_perms |= set(perms)

        # if the api is insert or update it's a write permission
        elif (base_api in CONTENT_RESOLVER_INSERT_API or
              base_api in CONTENT_RESOLVER_UPDATE_API):

            # if the base category matches one in the mapping,
            # add the relative permissions to the return set
            if base_cat in CONTENT_RESOLVER_WRITE_PERM_MAPPING:
                perms = CONTENT_RESOLVER_WRITE_PERM_MAPPING[base_cat]
                req_perms |= set(perms)

    return req_perms
