from rest_framework.views import APIView
from rest_framework.response import Response
from .ssh_client import run_ssh_command_on_go

class L2vpnView(APIView):
    def post(self, request):
        params = request.data
        result = run_ssh_command_on_go(
            host=params['host'],
            user=params['user'],
            password=params['password'],
            command=f"criar l2vpn {params['args']}"
        )
        return Response(result)
