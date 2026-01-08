import grpc
import os
import sys
sys.path.append(os.getcwd())
sys.stdout.reconfigure(line_buffering=True)
import logging
from concurrent import futures

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("Executor")
import subprocess
from common.proto import kuro_pb2
from common.proto import kuro_pb2_grpc

class ActionExecutor(kuro_pb2_grpc.ClientExecutorServicer):
    """
    Secure Client-side Executor.
    Executes ID-mapped actions from an allow-list.
    """
    def __init__(self):
        import os
        from pathlib import Path
        self.sandbox_path = Path.home() / "kuro_sandbox"
        self.sandbox_path.mkdir(exist_ok=True)
        
        # The Action Allow-list: Maps IDs to handler methods
        self.handlers = {
            "FS_READ": self._fs_read,
            "FS_LIST": self._fs_list,
        }

    def ExecuteAction(self, request, context):
        action_id = request.action_id
        if action_id not in self.handlers:
            return kuro_pb2.ActionResponse(success=False, error=f"Action ID '{action_id}' not in client allow-list.")
        
        params = request.params
        return self.handlers[action_id](params)

    def _fs_read(self, params):
        path_str = params.get("path")
        if not path_str:
             return kuro_pb2.ActionResponse(success=False, error="Missing 'path' parameter.")
        
        # Security: Enforce sandbox and file extension
        from pathlib import Path
        target = (self.sandbox_path / path_str).resolve()
        if not target.exists() or not target.is_file():
            return kuro_pb2.ActionResponse(success=False, error=f"File not found: {path_str}")
        
        if not str(target).startswith(str(self.sandbox_path)):
            return kuro_pb2.ActionResponse(success=False, error="Sandbox violation: Path is outside allowed directory.")
        
        if target.suffix != ".txt":
            return kuro_pb2.ActionResponse(success=False, error="Access denied: Only .txt files permitted.")

        try:
            with open(target, 'r') as f:
                return kuro_pb2.ActionResponse(success=True, output=f.read())
        except Exception as e:
            return kuro_pb2.ActionResponse(success=False, error=str(e))

    def _fs_list(self, params):
        try:
            files = [f.name for f in self.sandbox_path.glob("*.txt")]
            return kuro_pb2.ActionResponse(success=True, output="\n".join(files) if files else "Sandbox is empty.")
        except Exception as e:
            return kuro_pb2.ActionResponse(success=False, error=str(e))

    def RequestConfirmation(self, request, context):
        print(f"\n[KURO SAFETY] Confirmation Required: {request.message}")
        print(f"Severity: {request.severity}")
        choice = input("Approve action? (y/n): ")
        return kuro_pb2.ConfirmationResponse(approved=(choice.lower() == 'y'))

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=5))
    kuro_pb2_grpc.add_ClientExecutorServicer_to_server(ActionExecutor(), server)
    server.add_insecure_port('0.0.0.0:50054')
    print("Client Executor starting on port 50054...")
    server.start()
    server.wait_for_termination()

if __name__ == "__main__":
    serve()
