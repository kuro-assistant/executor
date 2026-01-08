import grpc
from concurrent import futures
import subprocess
from common.proto import kuro_pb2
from common.proto import kuro_pb2_grpc

class ActionExecutor(kuro_pb2_grpc.ClientExecutorServicer):
    """
    Secure Client-side Executor.
    Executes ID-mapped actions from an allow-list.
    """
    def __init__(self):
        # The Action Allow-list: Maps IDs to bash templates or Python functions
        self.allow_list = {
            "FS_LS": ["ls", "-la"],
            "FS_MOVE": ["mv"], # Requires validation of args
            "SYS_STAT": ["uptime"],
        }

    def ExecuteAction(self, request, context):
        action_id = request.action_id
        if action_id not in self.allow_list:
            return kuro_pb2.ActionResponse(success=False, error="Action ID not in allow-list.")
        
        # Execute the mapped action (Security: No raw shell)
        cmd = self.allow_list[action_id]
        
        # In a real app, we'd carefully sanitise and append params
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return kuro_pb2.ActionResponse(success=True, output=result.stdout)
        except subprocess.CalledProcessError as e:
            return kuro_pb2.ActionResponse(success=False, error=e.stderr)

    def RequestConfirmation(self, request, context):
        print(f"\n[KURO SAFETY] Confirmation Required: {request.message}")
        print(f"Severity: {request.severity}")
        choice = input("Approve action? (y/n): ")
        return kuro_pb2.ConfirmationResponse(approved=(choice.lower() == 'y'))

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=5))
    kuro_pb2_grpc.add_ClientExecutorServicer_to_server(ActionExecutor(), server)
    server.add_insecure_port('[::]:50054')
    print("Client Executor starting on port 50054...")
    server.start()
    server.wait_for_termination()

if __name__ == "__main__":
    serve()
