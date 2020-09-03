# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import re
from rally import exceptions
from rally.common import logging, validation, cfg
from rally.task import utils
from rally_openstack.common import consts, osclients
from rally_openstack.task.cleanup import manager as resource_manager
from rally_openstack.task import context, scenario
from rally_openstack.task.scenarios.nova import utils as nova_utils
from rally_openstack.task.scenarios.vm import utils as vm_utils
from rally_openstack.task import types
from rally_openstack.task.contexts.network import allow_ssh
from rally_openstack.common.services.image import image
from rally_openstack.task.scenario import OpenStackScenario as ops

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


# @validation.add("required_platform", platform="openstack", users=True)
# @context.configure(name="servers", platform="openstack", order=430)
# class ServerGenerator(context.OpenStackContext):
#    """Creates specified amount of Nova Servers per each tenant."""
#
#    CONFIG_SCHEMA = {
#        "type": "object",
#        "properties": {
#            "image": {
#                "description": "Name of image to boot server(s) from.",
#                "type": "object",
#                "properties": {
#                    "name": {"type": "string"}
#                },
#                "additionalProperties": False
#            },
#            "flavor": {
#                "description": "Name of flavor to boot server(s) with.",
#                "type": "object",
#                "properties": {
#                    "name": {"type": "string"}
#                },
#                "additionalProperties": False
#            },
#            "servers_per_tenant": {
#                "description": "Number of servers to boot in each Tenant.",
#                "type": "integer",
#                "minimum": 1
#            },
#            "auto_assign_nic": {
#                "description": "True if NICs should be assigned.",
#                "type": "boolean",
#            },
#            "nics": {
#                "type": "array",
#                "description": "List of networks to attach to server.",
#                "items": {"oneOf": [
#                    {
#                        "type": "object",
#                        "properties": {"net-id": {"type": "string"}},
#                        "description": "Network ID in a format like OpenStack "
#                                       "API expects to see.",
#                        "additionalProperties": False
#                    },
#                    {
#                        "type": "string",
#                        "description": "Network ID."
#                    }
#                ]},
#                "minItems": 1
#            }
#        },
#        "required": ["image", "flavor"],
#        "additionalProperties": False
#    }
#
#    DEFAULT_CONFIG = {
#        "servers_per_tenant": 5,
#        "auto_assign_nic": False
#    }
#
#    def setup(self):
#        image = self.config["image"]
#        flavor = self.config["flavor"]
#        auto_nic = self.config["auto_assign_nic"]
#        servers_per_tenant = self.config["servers_per_tenant"]
#        kwargs = {}
#        if self.config.get("nics"):
#            if isinstance(self.config["nics"][0], dict):
#                # it is a format that Nova API expects
#                kwargs["nics"] = list(self.config["nics"])
#            else:
#                kwargs["nics"] = [{"net-id": nic}
#                                  for nic in self.config["nics"]]
#
#        image_id = types.GlanceImage(self.context).pre_process(
#            resource_spec=image, config={})
#        flavor_id = types.Flavor(self.context).pre_process(
#            resource_spec=flavor, config={})
#
#        for iter_, (user, tenant_id) in enumerate(self._iterate_per_tenants()):
#            LOG.debug("Booting servers for user tenant %s" % user["tenant_id"])
#            tmp_context = {"user": user,
#                           "tenant": self.context["tenants"][tenant_id],
#                           "task": self.context["task"],
#                           "owner_id": self.context["owner_id"],
#                           "iteration": iter_}
#            nova_scenario = nova_utils.NovaScenario(tmp_context)
#
#            LOG.debug("Calling _boot_servers with image_id=%(image_id)s "
#                      "flavor_id=%(flavor_id)s "
#                      "servers_per_tenant=%(servers_per_tenant)s"
#                      % {"image_id": image_id,
#                         "flavor_id": flavor_id,
#                         "servers_per_tenant": servers_per_tenant})
#
#            servers = nova_scenario._boot_servers(image_id, flavor_id,
#                                                  requests=servers_per_tenant,
#                                                  auto_assign_nic=auto_nic,
#                                                  **kwargs)
#
#            current_servers = [server.id for server in servers]
#
#            LOG.debug("Adding booted servers %s to context" % current_servers)
#
#            self.context["tenants"][tenant_id][
#                "servers"] = current_servers
#
#    def cleanup(self):
#        resource_manager.cleanup(names=["nova.servers"],
#                                 users=self.context.get("users", []),
#                                 superclass=nova_utils.NovaScenario,
#                                 task_id=self.get_owner_id())
#

@validation.add("required_platform", platform="openstack", users=True)
@context.configure(name="servers_live_migrated", platform="openstack", order=300)
class ServersLiveMigrated(context.OpenStackContext):
    """Boot specified amount of Nova Servers then live migrate to another host."""

    CONFIG_SCHEMA = {
        "type": "object",
        "properties": {
            "vms_name": {
                "type": "array",
                "description": "List name of VMs",
                "items": {
                    "type": "string",
                }
            },
            "availability_zone": {
                "type": "string",
                "description": "Availability zone on which server created"
            },
            "hosts": {
                "type": "array",
                "description": "List of host will contain server",
                "items": {
                    "type": "string",
                    "description": "Name of host"
                }
            },
            "image": {
                "type": "string",
                "description": "Image uses for VMs",
            },
            "flavor": {
                "type": "string",
                "description": "Flavor uses for VMs",
            },
            "nics": {
                "type": "array",
                "description": "List of network to attach to server",
                "items": {"oneOf": [
                    {
                        "type": "object",
                        "properties": {"net-id": {"type": "string"}},
                        "description": "Network ID in a format like OpenStack "
                                       "API expects to see.",
                        "additionalProperties": False
                    },
                    {
                        "type": "string",
                        "description": "Network ID"
                    }
                ]},
                "minItems": 1
            },
            "username": {
                "type": "string"
            },
            "passphrase": {
                "type": "string"
            },
            "private_key_file": {
                "type": "string"
            },
            "public_key_file": {
                "type": "string"
            },
            "auto_clean": {
                "type": "boolean"
            },
        },
        "additionalProperties": False
    }

    def setup(self):
        self.context["vms"] = {"names": [], "ips": [], "ids": []}

        # Get private, public key file
        private_key = self.get_key_file(self.config["private_key_file"])
        public_key = self.get_key_file(self.config["public_key_file"])

        zone = self.config["availability_zone"]
        hosts = self.config["hosts"]
        image_name = self.config["image"]
        flavor_name = self.config["flavor"]
        vms_name = self.config["vms_name"]
        clients = osclients.Clients(self.context["admin"]["credential"])

        nova_client = clients.nova()
        image_id = self.validate_image(clients, image_name)
        flavor_id = self.validate_flavor(clients, flavor_name)
        # Create security group
        security_group_name = "permit-all"
        allow_ssh._prepare_open_secgroup(self.context["admin"]["credential"], security_group_name)

        # Create key_pair
        keypair_name = "check_live_migrate"
        self.validate_keypair(nova_client, keypair_name, public_key)
        self.validate_hypervisor_hostname(nova_client, zone, hosts)
        servers = []
        for vm_name in vms_name:
            index = vms_name.index(vm_name)
            hypervisor_hostname = "%s:%s" % (zone, hosts[index % len(hosts)])
            # Store info per vm
            self.context["vms"]["names"].append(vm_name)
            self.context["vms"]["hosts"].append(hypervisor_hostname)
            server = self.boot_server(nova_client, vm_name, hypervisor_hostname, keypair_name, security_group_name, index, image_id, flavor_id)
            servers.append(server)

        # Waiting for VM booting
        for server in servers:
            server = utils.wait_for_status(
                server,
                ready_statuses=["ACTIVE"],
                update_resource=utils.get_from_manager(),
                timeout=CONF.openstack.nova_server_boot_timeout,
                check_interval=CONF.openstack.nova_server_boot_poll_interval
            )

            fix_ip, float_ip = self.get_server_addr(server)
            print("Fix ip: %s, float ip: %s" % (fix_ip, float_ip))
            ssh_ip = fix_ip
            command = {"interpreter": "/bin/sh",
                       "script_inline": "uname"}
            self.context["vms"]["ips"].append({"fix": ssh_ip})
            self.context["vms"]["ids"].append(server.id)
            print(server.id)
        # Store global info
        self.context["vms"]["user"] = self.config["username"]
        self.context["vms"]["key"] = private_key
        self.context["vms"]["passphrase"] = self.config["passphrase"]

    def cleanup(self):
        delete = self.config["auto_clean"]
        if delete:
            LOG.info("Delete all vms created for testing %s" % str(self.config["auto_clean"]))
            clients = osclients.Clients(self.context["admin"]["credential"])
            nova_client = clients.nova()
            for index in range(len(self.context["vms"]["ids"])):
                self.delete_server(nova_client, index)

    def get_key_file(self, path):
        f = open(path, "r")
        key = f.read()
        f.close()
        return key

    def boot_server(self, nova_client, vm_name, hypervisor_hostname, keypair_name, security_group_name, index, image_id, flavor_id):
        # Assign network
        kwargs = {}
        self.assign_network(vm_name, kwargs, index)

        # Create new VM
        print("Create VM with name: " + vm_name + ", image_id: " + image_id
              + ", flavor_id: " + flavor_id + ", hypervisor_hostname: " + hypervisor_hostname + ", kwargs: "
              + str(kwargs["nics"]))
        server = nova_client.servers.create(name=vm_name,
                                            image=image_id,
                                            flavor=flavor_id,
                                            availability_zone=hypervisor_hostname,
                                            # host=host,
                                            security_groups=[security_group_name],
                                            key_name=keypair_name,
                                            min_count=1,
                                            max_count=1,
                                            **kwargs)
        return server

    def validate_image(self, clients, image_name):
        image_service = image.Image(clients)
        list_images = image_service.list_images()
        for image_ele in list_images:
            if image_ele["name"] == image_name:
                return image_ele.id
                break
        LOG.error("Can't get image %s" % image_name)
        return 0

    def validate_flavor(self, clients, flavor_name):
        nova_flavor = clients.nova().flavors
        list_flavors = nova_flavor.list()
        for flavor_ele in list_flavors:
            if flavor_ele.name == flavor_name:
                return flavor_ele.id

    def validate_keypair(self, nova_client, name, key):
        keypairs = nova_client.keypairs.list()
        for key_pair in keypairs:
            if key_pair.name == name:
                return
        nova_client.keypairs.create(name, key)

    def validate_hypervisor_hostname(self, nova_client, availability_zone, hypervisors):
        availability_zones = nova_client.availability_zones.list()
        for az in availability_zones:
            if az.zoneName == availability_zone:
                for host_name in hypervisors:
                    if host_name not in az.hosts.keys():
                        LOG.error("Compute %s not in AZ: %s" % (host_name, az.zoneName))
                        exit(1)

    def assign_network(self, name, kwargs, index):
        if isinstance(self.config["nics"][0], dict):
            kwargs["nics"] = list(self.config["nics"])
        else:
            num_net = len(self.config["nics"])
            kwargs["nics"] = [{"net-id": self.config["nics"][index % num_net]}]


    def get_server_addr(self, server):
        fix_ip = None
        float_ip = None
        networks = server.addresses
        for key, value in networks.items():
            for net in value:
                if net["OS-EXT-IPS:type"] == "fixed":
                    fix_ip = net["addr"]
                else:
                    float_ip = net["addr"]
        return fix_ip, float_ip

    def delete_server(self, nova_client, index):
        server_id = self.context["vms"]["ids"][index]
        server_name = self.context["vms"]["names"][index]
        try:
            LOG.info("Deleting server %s" % server_name)
            nova_client.servers.delete(server_id)
        except exceptions as e:
            LOG.error("Error occur when delete server %s: %s" % (server_name, e.message))


@validation.add("required_platform", platform="openstack", users=True)
@context.configure(name="servers_booted", platform="openstack", order=300)
class SeverBooted(context.OpenStackContext):
    """Boot specified amount of Nova Servers."""

    CONFIG_SCHEMA = {
        "type": "object",
        "properties": {
            "vms_name": {
                "type": "array",
                "description": "List name of VMs",
                "items": {
                    "type": "string",
                }
            },
            "zone": {
                "type": "string",
                "description": "Availability zone on which server created"
            },
            "hosts": {
                "type": "array",
                "description": "List of host will contain server",
                "items": {
                    "type": "string",
                    "description": "Name of host"
                }
            },
            "image": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"}
                },
                "additionalProperties": False
            },
            "flavor": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"}
                },
                "additionalProperties": False
            },
            "nics": {
                "type": "array",
                "description": "List of network to attach to server",
                "items": {"oneOf": [
                    {
                        "type": "object",
                        "properties": {"net-id": {"type": "string"}},
                        "description": "Network ID in a format like OpenStack "
                                       "API expects to see.",
                        "additionalProperties": False
                    },
                    {
                        "type": "string",
                        "description": "Network ID"
                    }
                ]},
                "minItems": 1
            },
            "username": {
                "type": "string"
            },
            "passphrase": {
                "type": "string"
            },
            "private_key_file": {
                "type": "string"
            },
            "public_key_file": {
                "type": "string"
            },
            "auto_clean": {
                "type": "boolean"
            },
        },
        "additionalProperties": False
    }

    def setup(self):
        self.context["vms"] = {"names": [], "ips": [], "ids": []}
        # Get nova client
        clients = osclients.Clients(self.context["admin"]["credential"])
        nova_client = clients.nova()

        # Get private, public key file
        private_key = self.get_key_file(self.config["private_key_file"])
        public_key = self.get_key_file(self.config["public_key_file"])

        vms_name = self.config["vms_name"]
        zone = self.config["zone"]
        hosts = self.config["hosts"]
        image_name = self.config["image"]
        flavor_name = self.config["flavor"]
        image_id = types.GlanceImage(self.context).pre_process(
            resource_spec=image_name, config={})
        flavor_id = types.Flavor(self.context).pre_process(
            resource_spec=flavor_name, config={})
        # Create security group
        security_group_name = "permit-all"
        allow_ssh._prepare_open_secgroup(self.context["admin"]["credential"], security_group_name)
        # Create key_pair
        keypair_name = "check_live_migrate"
        self.validate_keypair(nova_client, keypair_name, public_key)
        self.validate_hypervisor_hostname(nova_client, zone, hosts)

        servers = []
        for vm_name in vms_name:
            index = vms_name.index(vm_name)
            hypervisor_hostname = "%s:%s" % (zone, hosts[index % len(hosts)])
            # Store info per vm
            self.context["vms"]["names"].append(vm_name)
            self.context["vms"]["hosts"].append(hypervisor_hostname)
            server = self.boot_server(nova_client, vm_name, hypervisor_hostname, keypair_name, index, image_id,
                                      flavor_id)
            servers.append(server)
        for server in servers:
            server = utils.wait_for_status(
                server,
                ready_statuses=["ACTIVE"],
                update_resource=utils.get_from_manager(),
                timeout=CONF.openstack.nova_server_boot_timeout,
                check_interval=CONF.openstack.nova_server_boot_poll_interval
            )
            fix_ip, float_ip = self.get_server_addr(server)
            print("Fix ip: %s, float ip: %s" % (fix_ip, float_ip))
            ssh_ip = fix_ip
            # Save info all vm
            self.context["vms"]["ips"].append({"fix": ssh_ip})
            self.context["vms"]["ids"].append(server.id)
        # Save global info
        self.context["vms"]["user"] = self.config["username"]
        self.context["vms"]["key"] = private_key
        self.context["vms"]["passphrase"] = self.config["passphrase"]

    def cleanup(self):
        delete = self.config["auto_clean"]
        if delete:
            LOG.info("Delete all vms created for testing %s" % str(self.config["auto_clean"]))
            clients = osclients.Clients(self.context["admin"]["credential"])
            nova_client = clients.nova()
            for index in range(len(self.context["vms"]["names"])):
                self.delete_server(nova_client, index)

    def get_key_file(self, path):
        f = open(path, "r")
        key = f.read()
        f.close()
        return key

    def validate_keypair(self, nova_client, name, key):
        keypairs = nova_client.keypairs.list()
        for key_pair in keypairs:
            if key_pair.name == name:
                return
        nova_client.keypairs.create(name, key)

    def validate_hypervisor_hostname(self, nova_client, availability_zone, hypervisors):
        availability_zones = nova_client.availability_zones.list()
        for az in availability_zones:
            if az.zoneName == availability_zone:
                for host_name in hypervisors:
                    if host_name not in az.hosts.keys():
                        LOG.error("Compute %s not in AZ: %s" % (host_name, az.zoneName))
                        exit(1)

    def boot_server(self, nova_client, vm_name, hypervisor_hostname, keypair_name, index, image_id, flavor_id):
        # Assign network
        kwargs = {}
        self.assign_network(kwargs, index)
        LOG.info("Create VM with name: " + vm_name + ", image_id: " + image_id
                 + ", flavor_id: " + flavor_id + ", hypervisor hostname: " + hypervisor_hostname + ", kwargs: "
                 + str(kwargs["nics"]))
        server = nova_client.servers.create(name=vm_name,
                                            image=image_id,
                                            flavor=flavor_id,
                                            availability_zone=hypervisor_hostname,
                                            security_groups=["permit-all"],
                                            key_name=keypair_name,
                                            min_count=1,
                                            max_count=1,
                                            **kwargs)
        return server

    def assign_network(self, kwargs, index):
        if isinstance(self.config["nics"][0], dict):
            kwargs["nics"] = list(self.config["nics"])
        else:
            num_net = len(self.config["nics"])
            kwargs["nics"] = [{"net-id": self.config["nics"][index % num_net]}]

    def get_server_addr(self, server):
        float_ip = None
        fix_ip = None
        networks = server.addresses
        for key, value in networks.items():
            for net in value:
                if net["OS-EXT-IPS:type"] == "fixed":
                    fix_ip = net["addr"]
                else:
                    float_ip = net["addr"]
        return fix_ip, float_ip

    def delete_server(self, nova_client, index):
        server_id = self.context["vms"]["ids"][index]
        server_name = self.context["vms"]["names"][index]
        try:
            LOG.info("Deleting server %s" % server_name)
            nova_client.servers.delete(server_id)
        except exceptions as e:
            LOG.error("Error occur when delete server %s: %s" % (server_name, e.message))
