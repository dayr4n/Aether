from .config.settings import (
    HOST_AGENT_NAME,
    HOST_AGENT_VERSION,
    HOST_AGENT_IP,
    COLLECTION_DYNAMIC_INTERVAL,
    COLLECTION_STATIC_INTERVAL,
    DEBUG,
    LOG_LEVEL,
    SERVER_URL,
)
from .collectors import *
import time
import threading
import requests


class HostAgent:
    def __init__(self) -> None:
        self.version = HOST_AGENT_VERSION
        self.name = HOST_AGENT_NAME
        self.ip = HOST_AGENT_IP
        self.dynamic_collection_interval = COLLECTION_DYNAMIC_INTERVAL
        self.static_collection_interval = COLLECTION_STATIC_INTERVAL
        self.debug = DEBUG
        self.identity = {}
        self.dynamic_data = {}
        self.static_data = {}
        self.log_level = LOG_LEVEL

    # IDENTITY FUNCTION \ WITH THIS FUNCTION WE WILL GET THE HOST ID AND CLOSE IT INTO THE SELF.IDENTITY ATRIBUTE

    def get_identity(self):
        print("POSTING IDENTITY TO THE SERVER ..")
        id = {"agent": self.name, "version": self.version, "ip": self.ip}
        self.identity = id

    # STATIC AND DYNAMIC COLLECT \ HERE WE CAN SEE THE STATIC AND DYNAMIC COLLECT OF THE AGENT def get_static_data(self):
    def get_static_data(self):
        return {
            "ip": self.ip,
            "system": get_summary_system(),
            "users": get_summary_users(),
            "cpu_core": get_cpu_cores(),
        }

    def get_dynamic_data(self):
        return {
            "ip": self.ip,
            "cpu": get_summary_cpu(),
            "ram": get_summary_ram(),
            "processes": get_summary_processes(),
            "network": get_summary_network(),
            "disk": get_summary_disk(),
        }

    def get_full_data(self):
        return {
            **self.get_static_data(),
            **self.get_dynamic_data(),
        }

    # REGISTER REQUEST \ WITH THIS REQUEST WE WILL TELL THE SERVER WHAT'S OUR IP

    def register(self):
        self.get_identity()
        requests.post(f"{SERVER_URL}/agents/register", json=self.identity)

    # LOOPS \ HERE WE HAVE THE MAIN LOOPS FOR THE COLLECT...

    def get_dynamic_loop(self):
        while True:
            print("Dynamic data collect...")
            ddata = self.get_dynamic_data()
            self.dynamic_data = ddata
            try:
                requests.post(f"{SERVER_URL}/agents/dynamic", json=self.dynamic_data)
                time.sleep(self.dynamic_collection_interval)
            except requests.exceptions.RequestException:
                time.sleep(2)

    def get_static_loop(self):
        while True:
            print("Static data collect...")
            sdata = self.get_static_data()
            self.static_data = sdata
            try:
                requests.post(f"{SERVER_URL}/agents/static", json=self.static_data)
                time.sleep(self.static_collection_interval)
            except requests.exceptions.RequestException:
                time.sleep(2)

    # THREADS \ THIS THREADS CONTAIN THE MAIN TWO COLLECTS FOR THE AGENT , THE DYNAMIC AND STATIC COLLECT..

    def run(self):
        self.register()

        dynamic_thread = threading.Thread(target=self.get_dynamic_loop)

        static_thread = threading.Thread(target=self.get_static_loop)

        dynamic_thread.start()
        static_thread.start()

        dynamic_thread.join()
        static_thread.join()
