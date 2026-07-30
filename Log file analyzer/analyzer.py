import re
from collections import Counter


def analyze_logs(file):

    with open(file,"r") as f:
        logs=f.readlines()


    success=0
    failed=0

    users=[]
    ips=[]

    failed_users=[]
    failed_ips=[]


    for log in logs:


        if "LOGIN SUCCESS" in log:
            success+=1


        if "LOGIN FAILED" in log:
            failed+=1


        user=re.search(r"User:\s(\w+)",log)

        if user:
            username=user.group(1)
            users.append(username)

            if "LOGIN FAILED" in log:
                failed_users.append(username)



        ip=re.search(r"IP:\s([\d.]+)",log)

        if ip:
            address=ip.group(1)
            ips.append(address)

            if "LOGIN FAILED" in log:
                failed_ips.append(address)



    suspicious=[]

    for user,count in Counter(failed_users).items():

        if count>=3:

            suspicious.append(
                {
                "user":user,
                "attempts":count,
                "level":"HIGH"
                }
            )


    return {

        "total":len(logs),
        "success":success,
        "failed":failed,
        "users":len(set(users)),
        "ips":len(set(ips)),
        "suspicious":suspicious
    }
