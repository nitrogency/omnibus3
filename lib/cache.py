#!/usr/bin/env python3
##
# omnibus - deadbits.
#
# in-memory queue for keeping a list of recently active
# artifacts to be interacted with inside an omnibus session.
##

from redis import Redis
from lib.common import (
    error,
    get_option,
    utf_decode,
    utf_encode
)

class RedisCache:  
    def __init__(self, config):
        self.host = get_option('redis', 'host', config)
        self.port = int(get_option('redis', 'port', config))
        self.database = int(get_option('redis', 'db', config))
        self.ttl = 999999

        try:
            self.db = Redis(db=self.database, host=self.host,
                port=self.port, socket_timeout=None)
        except Exception as err:
            error(f'[redis] failed to connect to Redis (error: {str(err)})')
            self.db = None


    def receive(self, queue_name):
        """ Return most recent message from a given Redis queue"""
        try:
            ret_val = self.db.lindex(queue_name, -1)
            if isinstance(ret_val, bytes):
                return utf_decode(ret_val)
            return ret_val
        except Exception as err:
            error(f'[redis] failed to receive message from queue {queue_name} (error: {str(err)})')
            pass


    def delete(self, names):
        """ Remove one or more keys by name """
        try:
            self.db.delete(names)
        except Exception as err:
            error(f'[redis] failed to delete artifacts (error: {str(err)})')


    def exists(self, key):
        """ Check if value exists by key """
        return self.db.exists(key)


    def get(self, key):
        """ Get a value from redis by key """
        retval = self.db.get(key)
        if isinstance(retval, bytes):
            return utf_decode(retval)
        return retval


    def set(self, key, value, ttl=None):
        """ Set a value in cache with optional TTL """
        if ttl is None:
            ttl = self.ttl
        if isinstance(value, str):
            value = utf_encode(value)
        # backward compatibility (Redis v2.2)
        self.db.setnx(key, value)
        self.db.expire(key, ttl)


    def flush(self):
        """ Flush opened database entirely """
        self.db.flushdb()
