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

from rally.common import logging, cfg, broker
from rally.task import validation
from rally.task import utils
from rally import exceptions as rally_exceptions
from rally_openstack.common import consts
from rally_openstack.task import scenario
from rally_openstack.task.scenarios.vm import utils as vm_utils
from multiprocessing.dummy import Pool as ThreadPool
from gevent import monkey

"""Scenarios that are to be test network data plane of VM instances."""

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


@validation.add("required_services", services=[consts.Service.NOVA])
@validation.add("required_platform", platform="openstack", users=True)
@scenario.configure(context={"cleanup@openstack": ["nova"]},
                    name="VMTasks.check_live_migrate",
                    platform="openstack")
class CheckLiveMigrate(vm_utils.VMScenario):
    def run(self, host):
        """
        Migrates a running instance to a new machine.

        :param host: destination host name.
        """
        vms = self.context["vms"]
        self.context["destination_host"] = host
        number = len(vms["names"])
        # print("Number:%s" % number)
        monkey.patch_all()
        pool = ThreadPool(len(self.context["vms"]))
        pool.map(self.live_migrate_check, range(number))
        # print(vms["ids"])

    def live_migrate_check(self, index):
        vms = self.context["vms"]
        host = self.context["destination_host"]
        print("Destination host:%s" % host)
        server_id = vms["ids"][index]
        ssh_ip = vms["ips"][index]["fix"]
        ping_ips = [vms["ips"][i]["fix"] for i in range(len(vms["names"]))]
        ping_ips.remove(ssh_ip)
        # print(ping_ips)
        command = {"interpreter": "/bin/sh",
                   "script_inline": "ping %s" % ping_ips[0]}
        #        command = {"interpreter": "/bin/sh",
        #                   "script_inline": "ping 3.0.0.30" }
        print(command)
        server_admin = self.admin_clients(client_type="nova").servers.get(server_id)
        host_pre_migrate = getattr(server_admin, "OS-EXT-SRV-ATTR:host")
        LOG.info("Live migrate server %s" % vms["names"][index])
        server_admin.live_migrate(host=host, block_migration=False,
                                  disk_over_commit=False)
        LOG.info("Wait server %s become active" % vms["names"][index])
        utils.wait_for_status(
            server_admin,
            ready_statuses=["ACTIVE"],
            update_resource=utils.get_from_manager(),
            timeout=CONF.openstack.nova_server_live_migrate_timeout,
            check_interval=(
                CONF.openstack.nova_server_live_migrate_poll_interval)
        )
        try:
            code, out, err = self._run_command(server_ip=ssh_ip, port=22,
                                               username=vms["user"], password=vms["passphrase"],
                                               pkey=vms["key"], command=command, timeout=120)
        #            print("Code:"+ str(code))
        #            print("Out:"+ str(out))
        #            print("Error:"+ str(err))
        except (rally_exceptions.TimeoutException, rally_exceptions.SSHTimeout):
            console_logs = self._get_server_console_output(ssh_ip)
            LOG.info("VM console logs:\n%s" % console_logs)


@validation.add("required_services", services=[consts.Service.NOVA])
@validation.add("required_platform", platform="openstack", users=True)
@scenario.configure(context={"cleanup@openstack": ["nova"]},
                    name="VMTasks.check_migrate",
                    platform="openstack")
class CheckMigrate(vm_utils.VMScenario):
    def run(self):
        pass
        broker.run()


@validation.add("required_services", services=[consts.Service.NOVA])
@validation.add("required_platform", platform="openstack", users=True)
@scenario.configure(context={"cleanup@openstack": ["nova"]},
                    name="VMTasks.check_connection",
                    platform="openstack")
class CheckConnection(vm_utils.VMScenario):
    def run(self, num, local_path, remote_path):
        # pass
        # LOG.info("Number: %s" % num)
        self.context["local_path"] = local_path
        self.context["remote_path"] = remote_path
        self.context["output"] = {"Error": "", "Output": ""}
        self.context["output"]["Output"] = {}
        vms = self.context["vms"]
        number = len(vms["names"])
        LOG.info("Check names: %s" % str(vms["names"]))
        monkey.patch_all()
        pool = ThreadPool(len(self.context["vms"]))
        pool.map(self.wait_vm_boot_success, range(number))
        pool.map(self.check_connection, range(number))
        pool.close()
        print("%s" % str(self.context["output"]))
        # for node, ping_results in self.context["output"].items():
        #     for result in ping_results:
        #         self.add_output(**{node: result})
        verify_connection = self.context["output"]["Output"]
        self.add_output(complete={"title": "check_connection",
                                  "chart_plugin": "TextArea",
                                  "data": self.context["output"]})
        self.add_output(
            complete={"title": "Arbitrary Table",
                      "description": "Just show columns and rows as-is",
                      "chart_plugin": "Table",
                      "data": {"cols": ["header1", "header2", "header3"],
                               "rows": [["row1 col1", "col2", "col3"], ["row2 col1", 3, 4],
                                        ["row3 col1", 5, 6]]}})

        # Generate output
        destination_ips = list(verify_connection.keys())
        num_host = len(destination_ips)
        rows = []
        for i in range(num_host):
            rows.append(["OK" if i == k else verify_connection[destination_ips[i]][destination_ips[k]] for k in
                         range(num_host)])
        print(rows)
        for i in range(num_host):
            # self.context["vms"]["hosts"]
            rows[i].insert(0, "Compute:%s server:%s" % (vms["hosts"][i], destination_ips[i]))
        print(rows)
        cols = destination_ips
        cols.insert(0, "Name")
        self.add_output(
            complete={"title": "Verify connection",
                      "description": "Show results of state connections between vms",
                      "chart_plugin": "Table",
                      "data": {"cols": cols,
                               "rows": rows}
                      }
        )

    def wait_vm_boot_success(self, index):
        vms = self.context["vms"]
        server_id = vms["ids"][index]
        ssh_ip = vms["ips"][index]["fix"]
        command = {"interpreter": "/bin/sh", "script_inline": "uname"}
        LOG.info("Check server %s boot success yet" % vms["names"][index])
        try:
            code, out, err = self._run_command(server_ip=ssh_ip, port=22,
                                               username=vms["user"], password=vms["passphrase"],
                                               pkey=vms["key"], command=command, timeout=120)
            print("Error:" + str(err))
        except (rally_exceptions.TimeoutException, rally_exceptions.SSHTimeout):
            console_logs = self._get_server_console_output(ssh_ip)
            LOG.info("VM console logs:\n%s" % console_logs)

    def check_connection(self, index):
        vms = self.context["vms"]
        server_id = vms["ids"][index]
        ssh_ip = vms["ips"][index]["fix"]
        print("sship: %s" % ssh_ip)
        ping_ips = [vms["ips"][i]["fix"] for i in range(len(vms["names"]))]
        print("Index: %s" % index)
        ping_ips.remove(ssh_ip)
        # command = {"interpreter": "/bin/sh", "script_inline": "echo '0' >> /tmp/1.sh"}
        #                   "script_inline": "ping %s" % " ".join(ping_ips)}
        # command = {"local_path": self.context["local_path"], "remote_path": self.context["remote_path"],
        #            "command_args": " ".join(ping_ips)}
        command = {"interpreter": "/bin/sh",
                   "script_inline": "echo 'for i in $*; do ping -W 2 -c 2 \"$i\" > /dev/null;if [ $? -eq 0 ]; then "
                                    "echo \"$i OK\" | tee -a /tmp/1.txt;else echo \"$i NOK\" | tee -a "
                                    "/tmp/check.txt;fi;done ' > /tmp/check.sh && sh /tmp/check.sh %s" % " ".join(
                       ping_ips)}
        LOG.info("Command: %s" % command)
        server_admin = self.admin_clients(client_type="nova").servers.get(server_id)
        LOG.info("Running command on index %s server %s" % (index, vms["names"][index]))
        try:
            code, out, err = self._run_command(server_ip=ssh_ip, port=22,
                                               username=vms["user"], password=vms["passphrase"],
                                               pkey=vms["key"], command=command, timeout=20)
            print("Code:" + str(code))
            print("Out:" + str(out))
            print("Error:" + str(err))
            self.context["output"]["Output"][ssh_ip] = {}
            if out != '':
                out = out.split("\n")
                del out[-1]
                if isinstance(out, list):
                    for target in out:
                        sen = target.split(" ")
                        self.context["output"]["Output"][ssh_ip][sen[0]] = sen[1];
                else:
                    raise ValueError
            else:
                LOG.info("Output is empty")
                # for node in out: node = node.replace('\n', ''); sen = node.split(" "); data[ip][sen[0]] = sen[1];
        except (rally_exceptions.TimeoutException, rally_exceptions.SSHTimeout):
            console_logs = self._get_server_console_output(ssh_ip)
            LOG.info("VM console logs:\n%s" % console_logs)
        LOG.info("Check connection of server test complete")
