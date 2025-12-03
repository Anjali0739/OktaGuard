from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from .utils import Auth0Client
from django.views.decorators.csrf import csrf_exempt
import datetime
from collections import defaultdict
# Create your views here.



WORKING_HOURS_START = 9   
WORKING_HOURS_END = 18 


UNUSUAL_COUNTRIES = {"Russia", "China", "North Korea", "Brazil", "USA"}

logs = ""

@csrf_exempt
def oktaconnect(request):
    client = Auth0Client()
    logs = client.get_logs(per_page=50)
    if client:
        print("Auth0 Client initialized successfully.")
    return JsonResponse({"logs": logs})



def analyze_logs(logs):
    suspicious_reports = []

    # Group logs by user
    user_logs = defaultdict(list)
    for log in logs:
        user_logs[log["username"]].append(log)

    for user, entries in user_logs.items():
        # Sort by time
        entries.sort(key=lambda x: x["timestamp"])

        # A. Detect failed logins followed by a success
        for i in range(len(entries) - 1):
            if entries[i]["status"] == "failed" and entries[i+1]["status"] == "success":
                suspicious_reports.append({
                    "type": "BruteForceAttempt",
                    "username": user,
                    "failed_time": entries[i]["timestamp"],
                    "success_time": entries[i+1]["timestamp"],
                    "ip": entries[i]["ip"],
                })

        # B. Logins from unexpected countries
        for e in entries:
            if e["status"] == "success" and e["country"] in UNUSUAL_COUNTRIES:
                suspicious_reports.append({
                    "type": "UnexpectedCountryLogin",
                    "username": user,
                    "timestamp": e["timestamp"],
                    "country": e["country"],
                    "ip": e["ip"],
                })

        # C. Logins outside standard working hours
        for e in entries:
            log_time = datetime.datetime.fromisoformat(e["timestamp"])
            hour = log_time.hour

            if e["status"] == "success" and not (WORKING_HOURS_START <= hour <= WORKING_HOURS_END):
                suspicious_reports.append({
                    "type": "AfterHoursLogin",
                    "username": user,
                    "timestamp": e["timestamp"],
                    "hour": hour,
                    "ip": e["ip"],
                })

    return suspicious_reports