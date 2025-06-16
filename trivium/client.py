# client.py
import socket
import os
import json
import time
from typing import Dict, List
import matplotlib.pyplot as plt
from datetime import datetime

class EncryptionTester:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        
    def send_file(self, filename: str) -> Dict:
        with open(filename, 'rb') as f:
            data = f.read()
        
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.host, self.port))
        
        # Send file size
        client_socket.send(str(len(data)).encode())
        client_socket.recv(1024)  # Wait for ready signal
        
        # Send file data
        client_socket.send(data)
        
        # Receive statistics
        stats = json.loads(client_socket.recv(4096).decode())
        client_socket.close()
        
        return {
            'filename': os.path.basename(filename),
            'size_bytes': len(data),
            **stats
        }
    
    def process_directory(self, directory_path: str) -> List[Dict]:
        results = []
        
        # Process each file
        for filename in os.listdir(directory_path):
            if os.path.isfile(os.path.join(directory_path, filename)):
                file_path = os.path.join(directory_path, filename)
                print(f"\nProcessing {filename}...")
                
                result = self.send_file(file_path)
                results.append(result)
                
                print(f"Results for {filename}:")
                print(f"  Size: {result['size_bytes']/1024:.2f} KB")
                print(f"  Mean encryption time: {result['mean']*1000:.3f} ms")
                print(f"  Standard deviation: {result['std_dev']*1000:.3f} ms")
                print(f"  Min/Max: {result['min']*1000:.3f}/{result['max']*1000:.3f} ms")
        
        # Sort results by file size
        results.sort(key=lambda x: x['size_bytes'])
        
        return results
    
    def generate_report(self, results: List[Dict]) -> None:
        # Create timestamp for report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Print detailed results
        print("\nDetailed Encryption Time Results:")
        print("-" * 100)
        print(f"{'Filename':<20} {'Size (KB)':<12} {'Mean (ms)':<12} {'Median (ms)':<12} {'StdDev (ms)':<12} {'Min (ms)':<12} {'Max (ms)':<12}")
        print("-" * 100)
        
        for result in results:
            print(f"{result['filename']:<20} "
                  f"{result['size_bytes']/1024:<12.2f} "
                  f"{result['mean']*1000:<12.3f} "
                  f"{result['median']*1000:<12.3f} "
                  f"{result['std_dev']*1000:<12.3f} "
                  f"{result['min']*1000:<12.3f} "
                  f"{result['max']*1000:<12.3f}")
        
        # Generate plots
        plt.figure(figsize=(12, 6))
        
        # Plot 1: Size vs Mean Encryption Time
        plt.subplot(1, 2, 1)
        sizes = [r['size_bytes']/1024 for r in results]  # KB
        means = [r['mean']*1000 for r in results]  # ms
        plt.scatter(sizes, means)
        plt.xlabel('File Size (KB)')
        plt.ylabel('Mean Encryption Time (ms)')
        plt.title('File Size vs Encryption Time')
        
        # Plot 2: Distribution of times for largest file
        plt.subplot(1, 2, 2)
        largest_file = max(results, key=lambda x: x['size_bytes'])
        plt.boxplot([largest_file['mean']*1000], labels=[f"{largest_file['filename']}\n{largest_file['size_bytes']/1024:.1f}KB"])
        plt.ylabel('Encryption Time (ms)')
        plt.title('Time Distribution (Largest File)')
        
        plt.tight_layout()
        plt.savefig(f'encryption_analysis_{timestamp}.png')
        
        # Save detailed results to JSON
        with open(f'encryption_results_{timestamp}.json', 'w') as f:
            json.dump(results, f, indent=4)
        
        print(f"\nResults saved to encryption_results_{timestamp}.json")
        print(f"Plots saved to encryption_analysis_{timestamp}.png")

def main():
    directory_path = "./../generate_files"  # Change this to your directory path
    tester = EncryptionTester()
    results = tester.process_directory(directory_path)
    tester.generate_report(results)

if __name__ == "__main__":
    main()