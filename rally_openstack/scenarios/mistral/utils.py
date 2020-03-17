# Copyright 2015: Mirantis Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


from rally.common import cfg
from rally.task import atomic
from rally.task import utils
import yaml

from rally_openstack import scenario


CONF = cfg.CONF


class MistralScenario(scenario.OpenStackScenario):
    """Base class for Mistral scenarios with basic atomic actions."""

    @atomic.action_timer("mistral.list_workbooks")
    def _list_workbooks(self):
        """Gets list of existing workbooks.

        :returns: workbook list
        """
        return self.clients("mistral").workbooks.list()

    @atomic.action_timer("mistral.create_workbook")
    def _create_workbook(self, definition, namespace=''):
        """Create a new workbook.

        :param definition: workbook description in string
                           (yaml string) format
       :param namespace: the namespace where the workbook
                           will be created in
        :returns: workbook object
        """
        definition = yaml.safe_load(definition)
        definition["name"] = self.generate_random_name()
        definition = yaml.safe_dump(definition)

        return self.clients("mistral").workbooks.create(
            definition,
            namespace=namespace
        )

    @atomic.action_timer("mistral.delete_workbook")
    def _delete_workbook(self, wb_name, namespace=''):
        """Delete the given workbook.

        :param wb_name: the name of workbook that would be deleted.
        :param namespace: the namespace of workbook that would be deleted.
        """
        self.clients("mistral").workbooks.delete(
            wb_name,
            namespace=namespace
        )

    @atomic.action_timer("mistral.create_workflow")
    def _create_workflow(self, definition, namespace=''):
        """creates a workflow in the given namespace.

        :param definition: the definition of workflow
        :param namespace: the namespace of the workflow
        """
        return self.clients("mistral").workflows.create(
            definition,
            namespace=namespace
        )

    @atomic.action_timer("mistral.delete_workflow")
    def _delete_workflow(self, workflow_identifier, namespace=''):
        """Delete the given workflow.

        :param workflow_identifier: the identifier of workflow
        :param namespace: the namespace of the workflow
        """
        self.clients("mistral").workflows.delete(
            workflow_identifier,
            namespace=namespace
        )

    @atomic.action_timer("mistral.list_executions")
    def _list_executions(self, marker="", limit=None, sort_keys="",
                         sort_dirs=""):
        """Gets list of existing executions.

        :returns: execution list
        """

        return self.clients("mistral").executions.list(
            marker=marker, limit=limit, sort_keys=sort_keys,
            sort_dirs=sort_dirs)

    @atomic.action_timer("mistral.create_execution")
    def _create_execution(self, workflow_identifier, wf_input=None,
                          namespace='', **params):
        """Create a new execution.

        :param workflow_identifier: name or id of the workflow to execute
        :param namespace: namespace of the workflow to execute
        :param input_: json string of mistral workflow input
        :param params: optional mistral params (this is the place to pass
                       environment).
        :returns: executions object
        """

        execution = self.clients("mistral").executions.create(
            workflow_identifier,
            namespace=namespace,
            workflow_input=wf_input,
            **params
        )

        execution = utils.wait_for_status(
            execution, ready_statuses=["SUCCESS"], failure_statuses=["ERROR"],
            update_resource=utils.get_from_manager(),
            timeout=CONF.openstack.mistral_execution_timeout)

        return execution

    @atomic.action_timer("mistral.delete_execution")
    def _delete_execution(self, execution):
        """Delete the given execution.

        :param ex: the execution that would be deleted.
        """
        self.clients("mistral").executions.delete(execution.id)
