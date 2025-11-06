#!/usr/bin/env python3
"""
Emergency cleanup script to stop hanging Docker builds
Run this if your pipeline is stuck
"""

import subprocess
import sys

def cleanup_docker():
    """Stop all hanging Docker builds and clean up test images"""
    
    print("=" * 70)
    print("DOCKER CLEANUP UTILITY")
    print("=" * 70)
    
    # 1. Stop all running containers
    print("\n[1/4] Stopping all running containers...")
    try:
        result = subprocess.run(
            ["docker", "ps", "-q"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.stdout.strip():
            container_ids = result.stdout.strip().split('\n')
            for cid in container_ids:
                print(f"  Stopping container: {cid}")
                subprocess.run(["docker", "stop", cid], timeout=30, capture_output=True)
            print("  ✓ Containers stopped")
        else:
            print("  ✓ No running containers")
    except Exception as e:
        print(f"  ✗ Error: {e}")
    
    # 2. Remove test images
    print("\n[2/4] Removing test images...")
    try:
        result = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        test_images = [img for img in result.stdout.split('\n') if '_test_' in img]
        
        if test_images:
            for img in test_images:
                if img.strip():
                    print(f"  Removing: {img}")
                    subprocess.run(["docker", "rmi", "-f", img], capture_output=True, timeout=30)
            print(f"  ✓ Removed {len(test_images)} test images")
        else:
            print("  ✓ No test images found")
    except Exception as e:
        print(f"  ✗ Error: {e}")
    
    # 3. Prune build cache
    print("\n[3/4] Pruning build cache...")
    try:
        subprocess.run(
            ["docker", "builder", "prune", "-f"],
            timeout=30,
            capture_output=True
        )
        print("  ✓ Build cache pruned")
    except Exception as e:
        print(f"  ✗ Error: {e}")
    
    # 4. Show disk usage
    print("\n[4/4] Docker disk usage:")
    try:
        result = subprocess.run(
            ["docker", "system", "df"],
            capture_output=True,
            text=True,
            timeout=10
        )
        print(result.stdout)
    except Exception as e:
        print(f"  ✗ Error: {e}")
    
    print("\n" + "=" * 70)
    print("CLEANUP COMPLETE")
    print("=" * 70)
    print("\nYou can now restart your security pipeline.")
    print("The updated pipeline has:")
    print("  • Shorter timeouts (3 min max per build)")
    print("  • Better error handling")
    print("  • No invalid package versions")
    print("\nRestart with: python security_pipeline_main.py --interactive")

if __name__ == "__main__":
    try:
        cleanup_docker()
    except KeyboardInterrupt:
        print("\n\nCleanup interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nError: {e}")
        sys.exit(1)