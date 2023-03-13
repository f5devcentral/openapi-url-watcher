# Copyright (c) 2023 F5, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import hashlib
from urllib.request import urlopen
import optparse
import logging
import time
import time
import json
import subprocess
import sys
from kubernetes import client, config, dynamic
from kubernetes.dynamic.exceptions import ResourceNotFoundError
from kubernetes.client import api_client
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='%(asctime)s %(levelname)-8s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S')
logging.info('-----------Initialized OpenAPI URL watcher script-----------')

def get_remote_md5_sum(url):
    remote = urlopen(url)
    getHash = hash(remote)
    remote.close()
    return getHash

def hash(remote):
	max_file_size=100*1024*1024
	hash = hashlib.sha256()

	total_read = 0
	while True:
		data = remote.read(4096)
		total_read += 4096

		if not data or total_read > max_file_size:
			break

		hash.update(data)

	return hash.hexdigest()

def kube_config():
    try:
        config.load_incluster_config()
    except config.ConfigException:
        try:
            config.load_kube_config()
        except config.ConfigException:
            raise Exception('Could not configure kubernetes python client')

def reload():
    core_v1 = client.CoreV1Api()
    resp = None
    namespace = os.environ.get('NS', 'ingress')
    field_selector = 'metadata.namespace==' + namespace

    logging.info('Listing NGINX Ingress pods')
    ret = core_v1.list_pod_for_all_namespaces(field_selector=field_selector)
    for i in ret.items:
        name = i.metadata.name
        logging.info('Pod:' + name)

        try:
            resp = core_v1.read_namespaced_pod(name=name,
                                                    namespace=namespace)
        except ApiException as e:
            if e.status != 404:
                logging.info('Unknown error: %s' % e)
                exit(1)

        if not resp:
            logging.info('NGINX Ingress Pod %s does not exist' % name)

        exec_command = [
            '/bin/sh',
            '-c',
            '/opt/app_protect/bin/apreload']
        resp = stream(core_v1.connect_get_namespaced_pod_exec,
                      name,
                      namespace,
                      command=exec_command,
                      stderr=True, stdin=False,
                      stdout=True, tty=False)
        logging.info('NGINX App Protect Reload Response: ' + resp)


def main():
    kube_config()
    custom_object_api = client.CustomObjectsApi()
    policies_list = custom_object_api.list_cluster_custom_object(
        group="appprotect.f5.com", version="v1beta1", plural="appolicies"
)
    appolicies = json.dumps(policies_list)
    try:
        for item in policies_list['items']:
            policyname = item['metadata']['name']
            logging.info('Policy name: ' + policyname)
            url = None
            try:
                url = item['spec']['policy']['open-api-files'][0]['link']
            except KeyError:
                logging.info("Policy %s doesn't have OpenAPI URL reference. Skipping" % policyname)
            if url != None:
                logging.info('Policy OpenAPI URL: ' + url)
                new_hash = get_remote_md5_sum(url)
                logging.info('OpenAPI ref sha256: ' + new_hash)
                if os.path.exists(f'/var/tmp/$_{policyname}_.sha256'):
                    old_hash = open(f'/var/tmp/$_{policyname}_.sha256', "r")
                    oh = old_hash.readline()
                    logging.info('Old sha256: ' + oh)
                else:
                    old_hash = open(f'/var/tmp/$_{policyname}_.sha256', "w+")
                    old_hash.write(new_hash)
                    old_hash.close()
                    old_hash = open(f'/var/tmp/$_{policyname}_.sha256', "r")
                    oh = old_hash.readline()
                if new_hash != oh:
                    logging.info('External API reference ' + url + ' has changed! Reloading App Protect policy...')
                    reload()
                    old_hash.close()
                    os.remove(f'/var/tmp/$_{policyname}_.sha256')
                    f = open(f'/var/tmp/$_{policyname}_.sha256', "w+")
                    f.write(new_hash)
                    f.close()
    except:
        logging.info("Unable to get External OpenAPI URLs...")

if __name__ == "__main__":
    while True:
        try:
            main()
            time.sleep(60)
        except KeyboardInterrupt:
            logging.info('-----------Interrupted...Shutting Down-----------')
            try:
                sys.exit(130)
            except SystemExit:
                os._exit(130)
