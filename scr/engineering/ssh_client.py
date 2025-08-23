import requests

def run_ssh_command_on_go(host, user, password, command):
    data = {
        "host": host,
        "user": user,
        "password": password,
        "command": command,
    }
    resp = requests.post("http://go-ssh-service:8080/exec", json=data)
    return resp.json()
