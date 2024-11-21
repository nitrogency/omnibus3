#!/usr/bin/env python3
##
# omnibus - deadbits.
# mongodb interaction
##

import pymongo
from lib.common import error
from lib.common import warning
from lib.common import success
from lib.common import get_option


class Mongo:  
    def __init__(self, config):
        self._host = get_option('mongo', 'host', config)
        self._port = int(get_option('mongo', 'port', config))
        self._database = get_option('mongo', 'database', config)
        self._server = f'{self._host}:{self._port}'
        try:
            self.conn = pymongo.MongoClient(self._server)
        except Exception as err:
            error(f'failed to connect to Mongo instance: {str(err)}')
            raise err

        self.db = self.conn['mongo']
        self.collections = ['email', 'user', 'host', 'hash', 'bitcoin']


    def use_coll(self, collection):
        return self.db[collection]


    def get_value(self, collection, query, key):
        """ get value of given key from db query """
        coll = self.use_coll(collection)
        result = dict(coll.find_one(query, {key: 1}) or {})
        if result == {}:
            return None
        return result[key]


    def exists(self, collection, query):
        coll = self.use_coll(collection)
        result = coll.find_one(query)
        if result is None:
            return False
        return True


    def count(self, collection, query={}):
        coll = self.use_coll(collection)
        return coll.count_documents(query)  


    def insert_one(self, collection, data):
        if isinstance(data, object):
            data = data.__dict__

        coll = self.use_coll(collection)
        doc_id = None

        try:
            result = coll.insert_one(data)  
            doc_id = result.inserted_id
        except Exception as err:
            error(f'failed to index data: {str(err)}')
            pass

        return str(doc_id)


    def update_one(self, collection, query, new_data):
        coll = self.use_coll(collection)
        doc_id = None

        try:
            result = coll.update_one(query, {'$set': new_data})  
            doc_id = result.modified_count
        except Exception as err:
            error(f'failed to update documents: {query}')

        return doc_id


    def delete_one(self, collection, query):
        coll = self.use_coll(collection)
        try:
            coll.delete_one(query)  
        except Exception as err:
            error(f'failed to delete documents: {query}')
            pass


    def find_recent(self, collection, query={}, num_items=25, offset=0):
        coll = self.use_coll(collection)
        total = self.count(collection, query)
        result = []

        if total < num_items:
            result = list(coll.find(query))

        elif offset <= 0:
            result = list(coll.find(query).limit(num_items).sort([('_id', -1)]))

        else:
            result = list(coll.find(query).skip(offset).limit(num_items).sort([('_id', -1)]))

        return result


    def find(self, collection, query, one=False):
        """ return multiple query results as dict or single result as list """
        coll = self.use_coll(collection)

        if one:
            result = coll.find_one(query)

            if result is not None:
                d = dict(result)
                del d['_id']
                return d

            return {}

        else:
            result = coll.find(query)

            if result is not None:
                l = list(result)
                for i in l:
                    del i['_id']
                return l

            return []
