sessions = {}

def track_ip(ip):
    if ip not in sessions:
        sessions[ip] = 0
    sessions[ip] += 1
    return sessions[ip]