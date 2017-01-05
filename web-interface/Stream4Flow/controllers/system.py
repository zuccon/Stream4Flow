# -*- coding: utf-8 -*-
from __future__ import division
# Enable SHA-256 sum
import hashlib
# Enable random string generator
import random

import json, requests, urllib
# Enable to get current datetime
import os, subprocess
from datetime import datetime
# Import global functions
from global_functions import escape
from global_functions import check_username


# ----------------- Common Settings ------------------#


# Do not save the session for the all applications in the "system" controller
session.forget(response)



# ----------------- Users Management -----------------#


def users_management():
    """
    Show standard users management page with all users listed in the table.

    :return: Users as the table
    """

    # Get all users join with last login datetime
    users = db(db.users.id == db.users_logins.user_id).select()
    return dict(
        users=users
    )


def add_user():
    """
    Add a new user to the system (into the table users, users_auth, users_logins).

    :return: Users as the table and operation result alert message
    """

    # Default alert
    alert_type = "success"
    alert_message = ""
    error = False

    # Check mandatory inputs
    if not (
                                    request.post_vars.username and request.post_vars.name and request.post_vars.organization and request.post_vars.email and
                        request.post_vars.role and request.post_vars.password and request.post_vars.password_confirm):
        alert_type = "danger"
        alert_message = "Some mandatory input is missing!"
        error = True

    # Parse inputs
    username = escape(request.post_vars.username) if not error else ""
    name = escape(request.post_vars.name) if not error else ""
    organization = escape(request.post_vars.organization) if not error else ""
    email = escape(request.post_vars.email) if not error else ""
    role = escape(request.post_vars.role) if not error else ""
    password = escape(request.post_vars.password) if not error else ""
    password_confirm = escape(request.post_vars.password_confirm) if not error else ""

    # Check if username exists
    if not error and check_username(db, username):
        alert_type = "danger"
        alert_message = "Given username \"" + username + "\" already exists in the system!"
        error = True

    # Compare passwords
    if not error and (password != password_confirm):
        alert_type = "danger"
        alert_message = "Given passwords are different!"
        error = True

    # Insert user into tables
    if not error:
        # Insert into users table
        db.users.insert(username=username, name=name, organization=organization, email=email, role=role)
        # Get new user id
        user_id = db(db.users.username == username).select(db.users.id)[0].id
        # Generate salt and password
        salt = ''.join(
            random.choice('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') for i in range(20))
        hash = hashlib.sha256(salt + password).hexdigest()
        # Insert into users_auth table
        db.users_auth.insert(user_id=user_id, salt=salt, password=hash)
        # Set last login to default
        db.users_logins.insert(user_id=user_id, last_login=datetime.now())
        # Set success message
        alert_message = "User \"" + username + "\" successfully added to the system."

    # Get all users join with last login datetime
    users = db(db.users.id == db.users_logins.user_id).select()
    # Use standard view
    response.view = request.controller + '/users_management.html'
    return dict(
        alert_type=alert_type,
        alert_message=alert_message,
        users=users
    )


def delete_user():
    """
    Delete a given user from the system (from tables users, users_auth, users_logins).

    :return: Users as the table and operation result alert message
    """

    # Default alert
    alert_type = "success"
    alert_message = ""
    error = False

    # Check mandatory inputs
    if not request.post_vars.username:
        alert_type = "danger"
        alert_message = "Username not given!"
        error = True

    # Parse inputs
    username = escape(request.post_vars.username) if not error else ""

    # Check if username exists
    if not error and not check_username(db, username):
        alert_type = "danger"
        alert_message = "Given username \"" + username + "\" not exists in the system!"
        error = True

    # Delete user from all tables
    if not error:
        # Get user id
        user_id = db(db.users.username == username).select(db.users.id)[0].id
        # Delete from all users tables
        db(db.users.id == user_id).delete()
        db(db.users_auth.user_id == user_id).delete()
        db(db.users_logins.user_id == user_id).delete()
        # Set success message
        alert_message = "User \"" + username + "\" successfully deleted from the system."

    # Get all users join with last login datetime
    users = db(db.users.id == db.users_logins.user_id).select()
    # Use standard view
    response.view = request.controller + '/users_management.html'
    return dict(
        alert_type=alert_type,
        alert_message=alert_message,
        users=users
    )


def edit_user():
    """
    Update information about a given user.

    :return: Users as the table and operation result alert message
    """

    # Default alert
    alert_type = "success"
    alert_message = ""
    error = False

    # Check mandatory inputs
    if not (request.post_vars.username and request.post_vars.name and request.post_vars.organization and
                request.post_vars.email and request.post_vars.role):
        alert_type = "danger"
        alert_message = "Some mandatory input is missing!"
        error = True

    # Parse inputs
    username = escape(request.post_vars.username) if not error else ""
    name = escape(request.post_vars.name) if not error else ""
    organization = escape(request.post_vars.organization) if not error else ""
    email = escape(request.post_vars.email) if not error else ""
    role = escape(request.post_vars.role) if not error else ""

    # Check if username exists
    if not error and not check_username(db, username):
        alert_type = "danger"
        alert_message = "Given username \"" + username + "\" not exists in the system!"
        error = True

    # Check if user has correct permisions
    if not error and session.role == "user" and role != "user":
        alert_type = "danger"
        alert_message = "You do not have permission to update role of the user \"" + username + "\"!"
        error = True

    # Edit user in all users tables
    if not error:
        # Update table users
        db(db.users.username == username).update(name=name, organization=organization, email=email, role=role)
        # Set success message
        alert_message = "User \"" + username + "\" successfully updated."

    # Get all users join with last login datetime
    users = db(db.users.id == db.users_logins.user_id).select()
    # Use standard view.
    response.view = request.controller + '/users_management.html'
    return dict(
        alert_type=alert_type,
        alert_message=alert_message,
        users=users
    )


def change_password():
    """
    Set a new password for a given user.

    :return: Users as the table and operation result alert message
    """

    # Default alert
    alert_type = "success"
    alert_message = ""
    error = False

    # Check mandatory inputs
    if not (request.post_vars.username and request.post_vars.password_new and request.post_vars.password_confirm):
        alert_type = "danger"
        alert_message = "Some mandatory input is missing!"
        error = True

    # Parse inputs
    username = escape(request.post_vars.username) if not error else ""
    password_new = escape(request.post_vars.password_new) if not error else ""
    password_confirm = escape(request.post_vars.password_confirm) if not error else ""

    # Compare passwords
    if not error and (password_new != password_confirm):
        alert_type = "danger"
        alert_message = "Given passwords are different!"
        error = True

    # Set new password
    if not error:
        # Get user id
        user_id = db(db.users.username == username).select(db.users.id)[0].id
        # Get salt and generate a new hash
        salt = db(db.users_auth.user_id == user_id).select(db.users_auth.salt)[0].salt
        hash = hashlib.sha256(salt + password_new).hexdigest()
        # Update password
        db(db.users_auth.user_id == user_id).update(password=hash)
        # Set success message
        alert_message = "Password for the user \"" + username + "\" successfully changed."

    # Get all users join with last login datetime
    users = db(db.users.id == db.users_logins.user_id).select()
    # Use standard view
    response.view = request.controller + '/users_management.html'
    return dict(
        alert_type=alert_type,
        alert_message=alert_message,
        users=users
    )


# ----------------- About ----------------------------#


def about():
    """
    Show the main page of the About section.

    :return: Empty dictionary
    """
    return dict()


def applications():
    # Get duration and app information
    my_dict = {}
    final_dict = {}
    try:
        r = requests.get('http://10.16.31.211:8080/json/')
        r.encoding = 'UTF-8'
        data = r.json()

        applications_idct = dict(
         [(item["id"], (item["state"], item["name"], item["duration"], item["cores"], item["memoryperslave"])) for item
          in data["activeapps"]])
    except (requests.ConnectionError):
        return dict(
            alert_type2="danger",
            alert_message2="The cluster is not running!",
            applications=final_dict)

    for x in range(1, 5):
        try:
            s = requests.get('http://10.16.31.211:404' + str(x) + '/metrics/json/')
            s.encoding = 'UTF-8'
            records = s.json()
            for key, values in records.iteritems():
                if key == "gauges":
                    for keygauge, valgauge in values.iteritems():
                        if "StreamingMetrics.streaming.totalReceivedRecords" in keygauge:
                            my_dict[keygauge] = valgauge.values()[0]
                            break

        except (ValueError, IOError):
            continue


    for id, (state, name, duration, cores, memory) in applications_idct.items():
        if state == "RUNNING":
            for appid, records in my_dict.items():
                if id in appid:
                    runningTime = duration / 3600000
                    averageRPS = records / (duration / 1000)
                    timeInHours = str(round(runningTime, 2))
                    final_dict[id] = [name, timeInHours, records, averageRPS, cores, memory]

    return dict(applications=final_dict)


def cluster():
    workers_idct = {}
    try:
        urlWorkers = 'http://10.16.31.211:8080/json/'
        responseWorkers = urllib.urlopen(urlWorkers)
        dataWorkers = json.loads(responseWorkers.read())
        workers_idct = {}
        for item in dataWorkers["workers"]:
            if item["state"] == "ALIVE":
                workers_idct[item["id"]] = [item["webuiaddress"], item["cores"], item["memory"], item["state"]]
    except(ValueError, IOError):
        print "Cluster nebezi"

    return dict(workers=workers_idct)


def clusterStart():

    url = "http://10.16.31.211:3031/cluster/start"
    responseCluster = urllib.urlopen(url)
    dataCluster = responseCluster.read()

    if "Cluster was already running!" == dataCluster:
        alert_type2="danger"

    if "Cluster sucessfully started!" == dataCluster:
        alert_type2 = "success"

    workers_idct = {}
    try:
        urlWorkers = 'http://10.16.31.211:8080/json/'
        responseWorkers = urllib.urlopen(urlWorkers)
        dataWorkers = json.loads(responseWorkers.read())
        workers_idct = {}
        for item in dataWorkers["workers"]:
            if item["state"] == "ALIVE":
                workers_idct[item["id"]] = [item["webuiaddress"], item["cores"], item["memory"], item["state"]]
    except(ValueError, IOError):
        print "Cluster nebezi"

    response.view = request.controller + '/cluster.html'
    return dict(
        alert_type2=alert_type2,
        alert_message2=dataCluster,
        workers=workers_idct
    )


def clusterKill():
    url = "http://10.16.31.211:3031/cluster/kill"
    responseCluster = urllib.urlopen(url)
    dataCluster = responseCluster.read()

    if "Cluster was already not running!" == dataCluster:
        alert_type2="danger"

    if "Cluster sucessfully killed!" == dataCluster:
        alert_type2 = "success"

    workers_idct = {}
    try:
        urlWorkers = 'http://10.16.31.211:8080/json/'
        responseWorkers = urllib.urlopen(urlWorkers)
        dataWorkers = json.loads(responseWorkers.read())
        workers_idct = {}
        for item in dataWorkers["workers"]:
            if item["state"] == "ALIVE":
                workers_idct[item["id"]] = [item["webuiaddress"], item["cores"], item["memory"], item["state"]]
    except(ValueError, IOError):
        print "Cluster nebezi"

    response.view = request.controller + '/cluster.html'
    return dict(
        alert_type2=alert_type2,
        alert_message2=dataCluster,
        workers=workers_idct
    )




def startApplication():
    my_dict = {}
    final_dict = {}
    selectApplication = request.post_vars.get('application')
    selectMemory = request.post_vars.get('cores')
    selectCores = request.post_vars.get('cores')

    if (selectApplication == None or selectApplication == None or selectCores == None):
         alert_type2 = "danger"
         alert_message = "Missing some parameter"

    else:
        alert_type2 = "success"
        alert_message = "Application " + selectApplication + " started!"
        url = "http://10.16.31.211:3031/" +selectApplication + "/cores=" +str(selectCores) + "/memory=" + str(selectMemory)
        data = requests.get(url).json

    try:
        r = requests.get('http://10.16.31.211:8080/json/')
        r.encoding = 'UTF-8'
        data = r.json()

        applications_idct = dict(
            [(item["id"], (item["state"], item["name"], item["duration"], item["cores"], item["memoryperslave"])) for item in data["activeapps"]])

    except (requests.ConnectionError):
        response.view = request.controller + '/applications.html'
        return dict(
            alert_type2="danger",
            alert_message2="You cannot run application because the cluster is not running!",
            applications=final_dict)



    for x in range(1, 5):
        try:
            s = requests.get('http://10.16.31.211:404' + str(x) + '/metrics/json/')
            s.encoding = 'UTF-8'
            records = s.json()
            for key, values in records.iteritems():
                if key == "gauges":
                    for keygauge, valgauge in values.iteritems():
                        if "StreamingMetrics.streaming.totalReceivedRecords" in keygauge:
                            my_dict[keygauge] = valgauge.values()[0]
                            break

        except (ValueError, IOError):
            continue


    for id, (state, name, duration,cores,memory) in applications_idct.items():
        if state == "RUNNING":
            for appid, records in my_dict.items():
                if id in appid:
                    runningTime = duration / 3600000
                    averageRPS = records / (duration / 1000)
                    timeInHours = str(round(runningTime, 2))
                    final_dict[id] = [name, timeInHours, records, averageRPS,cores,memory]

    response.view = request.controller + '/applications.html'
    return dict(
            alert_type2=alert_type2,
            alert_message2=alert_message,
            applications=final_dict
        )

def killApplication():
    selectApplication = request.post_vars.get('appname')
    if "protocols_statistics" in selectApplication:

        requests.get('http://10.16.31.211:3031/protocols_statistics/kill')
        alert_type2 = "success"


    if "traffic-profiles.py" in selectApplication:
            requests.get('http://10.16.31.211:3031/traffic_profiles/kill')
            alert_type2 = "success"


    alert_message = "Application " + selectApplication + " killed!"


    r = requests.get('http://10.16.31.211:8080/json/')
    r.encoding = 'UTF-8'
    data = r.json()

    applications_idct = dict(
        [(item["id"], (item["state"], item["name"], item["duration"], item["cores"], item["memoryperslave"])) for item
         in data["activeapps"]])

    my_dict = {}
    for x in range(1, 5):
        try:
            s = requests.get('http://10.16.31.211:404' + str(x) + '/metrics/json/')
            s.encoding = 'UTF-8'
            records = s.json()
            for key, values in records.iteritems():
                if key == "gauges":
                    for keygauge, valgauge in values.iteritems():
                        if "StreamingMetrics.streaming.totalReceivedRecords" in keygauge:
                            my_dict[keygauge] = valgauge.values()[0]
                            break

        except (ValueError, IOError):
            continue

    final_dict = {}
    for id, (state, name, duration, cores, memory) in applications_idct.items():
        if state == "RUNNING":
            for appid, records in my_dict.items():
                if id in appid:
                    runningTime = duration / 3600000
                    averageRPS = records / (duration / 1000)
                    timeInHours = str(round(runningTime, 2))
                    final_dict[id] = [name, timeInHours, records, averageRPS, cores, memory]

    response.view = request.controller + '/applications.html'
    return dict(
        alert_type2=alert_type2,
        alert_message2=selectApplication,
        applications=final_dict
    )