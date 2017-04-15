# -*- coding: utf-8 -*-
from __future__ import division
# Enable SHA-256 sum
import hashlib
# Enable random string generator
import random
import time

import re
import sys
from time import sleep
from datetime import datetime
import time

import json, requests, urllib
# Enable to get current datetime
import os, subprocess

# Import global functions
from global_functions import escape,check_username

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

# ----------------- Applications ----------------------------#

#Get all applications

def get_applications():
    my_dict = {}
    final_dict = {}


    try:
        r = requests.get('http://10.16.31.210:8080/json/')
        r.encoding = 'UTF-8'
        data = r.json()

        applications_idct = dict(
            [(item["id"], (item["state"], item["name"], item["duration"], item["cores"], item["memoryperslave"])) for
             item
             in data["activeapps"]])
    except (requests.ConnectionError):
        return dict(
            alert_type2="danger",
            alert_message2="The cluster is not running!",
            applications=final_dict)

    if not applications_idct:
        return final_dict

    for row in db().select(db.applications.application_id):
        try:
            s = requests.get('http://10.16.31.210:' + str(row.application_id) + '/metrics/json/')
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

    if not my_dict:
        return final_dict

    for id, (state, name, duration, cores, memory) in applications_idct.items():
        if state == "RUNNING":
            for appid, records in my_dict.items():
                if id in appid:
                    runningTime = duration / 3600000
                    averageRPS = records / (duration / 1000)
                    timeInHours = str(round(runningTime, 2))

                    now = datetime.now()

                    port = db(db.applications.application_name == id).select(db.applications.application_port)[0].application_port
                    #add the difference in records
                    try:
                        lastValue = db(db.performance.application_id == port).select(db.performance.application_timestamp,db.performance.application_records).sort(lambda row: row.application_timestamp, reverse=True)[0].application_records
                        if lastValue is None:
                           difference=0
                        else:
                           difference = records - lastValue
                    except(IndexError):
                        difference = 0

                    db.performance.insert(application_id=port,application_timestamp=now,
                                          application_running_time=runningTime,application_records=records,
                                          application_average_records=difference)
                    final_dict[id] = [name, timeInHours, records, averageRPS, cores, memory,str(port)]

    return final_dict

def applications():
    return dict(applications=get_applications())

def applicationDetail():

    chosenApplication = request.post_vars.get('appport')

    return dict(applications=get_applications(),applicationWanted=str(chosenApplication))

#Prepares the data for highchart graph
def get_statistics():
    port = escape(request.get_vars.port)
    data = ""

    for row in db(db.performance.application_id == port).select(db.performance.application_average_records, db.performance.application_timestamp):
        timestampFinal = int(time.mktime(time.strptime(str(row.application_timestamp), '%Y-%m-%d %H:%M:%S'))) * 1000
        data += str(timestampFinal) + "," + str(row.application_average_records) + ";"

    json_response = '{"data": "' + data + '"}'

    return json_response

def startApplication():

    selectApplication = request.post_vars.get('application')
    selectMemory = request.post_vars.get('cores')
    selectCores = request.post_vars.get('cores')
    selectPort = request.post_vars.get('port')
    if (selectApplication == None or selectApplication == None or selectCores == None):
         alert_type2 = "danger"
         alert_message = "Missing some parameter"

    else:

            if db(db.applications.application_port == selectPort).count() != 0:
                alert_type2 = "danger"
                alert_message = "This port is already busy!"

            else:
                alert_type2 = "success"
                alert_message = "Application " + selectApplication + " started!"
                url = "http://10.16.31.210:3031/" +selectApplication + "/cores=" +str(selectCores) + "/memory=" + str(selectMemory) +"/port="+str(selectPort)
                data = requests.get(url).json

    app_id= getAppID(str(selectPort))

    db.applications.insert(application_id=selectPort, application_name=app_id, application_cores=selectCores,
                           application_memory=selectMemory, application_port=selectPort)

    running_apps_dict = get_applications()

    response.view = request.controller + '/applications.html'
    return dict(
            alert_type2=alert_type2,
            alert_message2=alert_message,
            applications=running_apps_dict
        )

def getAppID(port):
        sleep(10)
        url = "http://10.16.31.210:"+port+"/metrics/json/"
        s = requests.get(url)
        s.encoding = 'UTF-8'
        records = s.json()
        myre = '^(app-\d*-\d*).driver.\w+'

        for key, values in records.iteritems():
            if key == "gauges":
                for keygauge, valgauge in values.iteritems():
                    application_ID = values.keys()[0]
                    if re.search(myre, values.keys()[0]):
                        application_ID = re.search(myre, values.keys()[0]).group(1)



        return application_ID


def killApplication():
    selectPort = request.post_vars.get('appport')
    db(db.applications.application_port == selectPort).delete()
    db(db.performance.application_id == selectPort).delete()
    url = "http://10.16.31.210:3031/application/kill/port= "+selectPort
    requests.get(url)
    alert_type2 = "success"

    alert_message = "Application " + selectPort + " killed!"

    running_apps_dict = get_applications()

    response.view = request.controller + '/applications.html'
    return dict(
        alert_type2=alert_type2,
        alert_message2=alert_message,
        applications=running_apps_dict
    )

# ----------------- Cluster ----------------------------#

def cluster_info():
    workers_idct = {}
    try:
        urlWorkers = 'http://10.16.31.210:8080/json/'
        responseWorkers = urllib.urlopen(urlWorkers)
        dataWorkers = json.loads(responseWorkers.read())
        workers_idct = {}
        for item in dataWorkers["workers"]:
            if item["state"] == "ALIVE":
                workers_idct[item["id"]] = [item["webuiaddress"], item["cores"], item["memory"], item["state"],item["host"]]
    except(ValueError, IOError):
        print "Cluster nebezi"


    return workers_idct

def cluster():
    listHosts = []
    #My workers
    allHosts = ["10.16.31.210","10.16.31.212","10.16.31.213","10.16.31.214","10.16.31.211"]

    currentStatus={}
    active_workers = cluster_info()

    #Currently running workers
    for id, (webuiaddress, cores, memory, state, host) in active_workers.iteritems():
        listHosts.append(host)

    #If there is at least 1 worker that means that the master is running
    if len(listHosts) != 0:
        listHosts.append("10.16.31.210")


    for i, val in enumerate(allHosts):
        if val in listHosts:
            currentStatus[val]="OK"
        else: currentStatus[val]="NOK"

    return dict(workers=active_workers,listHosts=currentStatus)

def clusterStart():

    listHosts = []
    #My workers
    allHosts = ["10.16.31.210","10.16.31.212","10.16.31.213","10.16.31.214","10.16.31.211"]
    currentStatus = {}

    url = "http://10.16.31.210:3031/cluster/start"
    responseCluster = urllib.urlopen(url)
    dataCluster = responseCluster.read()

    alert_message2="Cluster started!"
    alert_type2 = "success"

    active_workers = cluster_info()

    # Currently running workers
    for id, (webuiaddress, cores, memory, state, host) in active_workers.iteritems():
        listHosts.append(host)

    # If there is at least 1 worker that means that the master is running
    if len(listHosts) != 0:
        listHosts.append("10.16.31.210")

    for i, val in enumerate(allHosts):
        if val in listHosts:
            currentStatus[val] = "OK"
        else:
            currentStatus[val] = "NOK"


    response.view = request.controller + '/cluster.html'
    return dict(
        alert_type2=alert_type2,
        alert_message2= alert_message2,
        workers=active_workers,
        listHosts=currentStatus,
    )


def clusterKill():
    url = "http://10.16.31.210:3031/cluster/stop"
    responseCluster = urllib.urlopen(url)
    dataCluster = responseCluster.read()

    alert_message2 = "Cluster stopped!"
    alert_type2 = "success"

    active_workers = cluster_info()

    ###
    listHosts = []
    # My workers
    allHosts = ["10.16.31.210", "10.16.31.212", "10.16.31.213", "10.16.31.214", "10.16.31.211"]
    currentStatus = {}

    # Currently running workers
    for id, (webuiaddress, cores, memory, state, host) in active_workers.iteritems():
        listHosts.append(host)

    # If there is at least 1 worker that means that the master is running
    if len(listHosts) != 0:
        listHosts.append("10.16.31.210")

    for i, val in enumerate(allHosts):
        if val in listHosts:
            currentStatus[val] = "OK"
        else:
            currentStatus[val] = "NOK"

    response.view = request.controller + '/cluster.html'
    return dict(
        alert_type2=alert_type2,
        alert_message2= alert_message2,
        workers=active_workers,
        listHosts=currentStatus
    )



