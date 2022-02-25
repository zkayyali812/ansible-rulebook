
import durable.lang

from typing import Dict, List
import ansible_runner
import shutil
import tempfile
import os
import yaml


def assert_fact(inventory: Dict, hosts: List, ruleset: str, fact: Dict):
    durable.lang.assert_fact(ruleset, fact)


def retract_fact(inventory: Dict, hosts: List, ruleset: str, fact: Dict):
    durable.lang.retract_fact(ruleset, fact)


def post_event(inventory: Dict, hosts: List, ruleset: str, fact: Dict):
    durable.lang.post(ruleset, fact)


def run_playbook(inventory: Dict, hosts: List, name: str, **kwargs):

    temp = tempfile.mkdtemp(prefix='run_playbook')
    print(temp)

    os.mkdir(os.path.join(temp, 'env'))
    os.mkdir(os.path.join(temp, 'inventory'))
    with open(os.path.join(temp, 'inventory', 'hosts'), 'w') as f:
        f.write(yaml.dump(inventory))
    os.mkdir(os.path.join(temp, 'project'))

    shutil.copy(name, os.path.join(temp, 'project', name))

    host_limit = ",".join(hosts)

    ansible_runner.run(playbook=name, private_data_dir=temp, limit=host_limit)


actions = dict(assert_fact=assert_fact,
               retract_fact=retract_fact,
               post_event=post_event,
               run_playbook=run_playbook)
