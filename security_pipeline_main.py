#!/usr/bin/env python3

"""
Universal Container Security Pipeline - Main Entry Point
Integrates: Image Security, Pod Security, and Security Chatbot
UPDATED: Now supports scanning from Kubernetes cluster
"""

import argparse
import sys
import logging
import datetime
import json
from pathlib import Path
from typing import List, Optional

from image_security import ImageSecurityAnalyzer
from pod_security import PodSecurityAnalyzer
from chatbot import SecurityChatbot
from common import EnhancedSecurityPipeline

# Ensure UTF-8 encoding
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if sys.stderr.encoding != 'utf-8':
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


def setup_pipeline():
    """Initialize core pipeline"""
    return EnhancedSecurityPipeline()


def interactive_menu(pipeline):
    """Interactive 3-option menu"""
    while True:
        print("\n" + "="*70)
        print("🔒 UNIVERSAL CONTAINER SECURITY PIPELINE")
        print("="*70)
        print("\nSelect an option:")
        print("1) Image Security – list local Docker images")
        print("2) Pod Security – list/scan Kubernetes resources")
        print("3) Chatbot – open security assistant")
        print("q) Quit")
        print("="*70)
        choice = input("Choose (1/2/3/q): ").strip().lower()

        if choice == '1':
            handle_image_analysis(pipeline)
        elif choice == '2':
            handle_pod_analysis(pipeline)
        elif choice == '3':
            handle_chatbot(pipeline)
        elif choice in ['q', 'quit', 'exit']:
            print("Exiting. Goodbye! 👋")
            break
        else:
            print("❌ Invalid choice")


def handle_image_analysis(pipeline):
    """Handle image security workflow"""
    print("\n" + "="*70)
    print("🐳 IMAGE SECURITY ANALYSIS")
    print("="*70)
    
    image_analyzer = ImageSecurityAnalyzer(pipeline)
    
    images = image_analyzer.list_docker_images()
    image_analyzer.pretty_print_list(images, title="Local Docker Images")
    
    if images:
        save = input("\n💾 Save list to outputs/scans/docker_images.json? (y/n): ").strip().lower()
        if save in ['y', 'yes']:
            outpath = pipeline.scans_dir / f"docker_images_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(outpath, 'w', encoding='utf-8') as f:
                json.dump(images, f, indent=2)
            print(f"✅ Saved: {outpath}")

        run_full = input("\n🔍 Run full scan & remediation for an image? (y/n): ").strip().lower()
        if run_full in ['y', 'yes']:
            names = [it.get('name') for it in images]
            print("\nAvailable images:")
            for i, n in enumerate(names, start=1):
                print(f"  {i}) {n}")
            sel = input("\nEnter number or paste image name: ").strip()
            sel_image = None
            
            if sel.isdigit():
                si = int(sel) - 1
                if 0 <= si < len(names):
                    sel_image = names[si]
            else:
                sel_image = sel or None

            if sel_image:
                print(f"\n🚀 Starting full pipeline for: {sel_image}")
                
                # Initialize RAG
                pipeline.setup_rag_system()
                
                # Run image pipeline
                try:
                    results = image_analyzer.run_image_pipeline(sel_image)
                    
                    print("\n" + "="*70)
                    print("✅ IMAGE ANALYSIS COMPLETE")
                    print("="*70)
                    print(f"\n📊 Summary:")
                    print(f"   Total vulnerabilities: {results['total_vulnerabilities']}")
                    print(f"   Fixable vulnerabilities: {results['fixable_vulnerabilities']}")
                    print(f"   Technology stack: {', '.join(results['image_info']['technology_stack'])}")
                    print(f"   Base OS: {results['image_info']['base_os']}")
                    
                    print(f"\n📄 Report: {results['report_file']}")
                    
                    if results.get('dockerfile_path'):
                        print(f"🔒 Secured Dockerfile: {results['dockerfile_path']}")
                    
                    if results.get('validation'):
                        validation = results['validation']
                        if validation.get('status') == 'success':
                            print(f"\n✅ Validation: Secured image created and validated!")
                            print(f"   Secured image: {validation.get('secured_image')}")
                            print(f"   Improvement: {validation['comparison']['improvement']} fewer critical/high vulnerabilities")
                        elif validation.get('status') == 'no_improvement':
                            print(f"\n⚠️ Validation: No significant improvement detected")
                        elif validation.get('status') == 'validation_skipped_missing_files':
                            print(f"\n⚠️ Validation: Skipped (requires project files)")
                            print(f"   Note: {validation.get('message')}")
                    
                    print("="*70)
                    
                except Exception as e:
                    print(f"\n❌ Error: {e}")
                    logging.error(f"Image pipeline failed: {e}", exc_info=True)
            else:
                print("❌ No valid image selected")


def handle_pod_analysis(pipeline):
    """Handle pod security workflow - NOW WITH CLUSTER SUPPORT"""
    print("\n" + "="*70)
    print("☸️ POD SECURITY ANALYSIS")
    print("="*70)
    
    pod_analyzer = PodSecurityAnalyzer(pipeline)
    
    # Ask user: scan local files or cluster resources?
    print("\nChoose scan source:")
    print("1) Local YAML files (scan files from disk)")
    print("2) Kubernetes cluster (extract & scan running resources)")
    print("3) Cancel")
    
    source_choice = input("\nYour choice (1/2/3): ").strip()
    
    if source_choice == '1':
        handle_local_yaml_scan(pipeline, pod_analyzer)
    elif source_choice == '2':
        handle_cluster_resource_scan(pipeline, pod_analyzer)
    else:
        print("❌ Cancelled")


def handle_local_yaml_scan(pipeline, pod_analyzer):
    """Handle scanning local YAML files"""
    # Search for YAML files
    yaml_files = list(Path('.').rglob('*.yaml')) + list(Path('.').rglob('*.yml'))
    
    # Filter out excluded directories
    excluded_dirs = {'outputs', '.git', 'node_modules', 'venv', '__pycache__', 'vendor'}
    filtered_files = [
        f for f in yaml_files 
        if not any(part in excluded_dirs for part in f.parts)
    ]
    
    if not filtered_files:
        print("\n❌ No YAML files found")
        
        # Allow manual input
        manual = input("\nEnter manifest paths manually? (y/n): ").strip().lower()
        if manual in ['y', 'yes']:
            handle_manual_manifest_input(pipeline, pod_analyzer)
        return
    
    print(f"\n📋 Found {len(filtered_files)} YAML files\n")
    print(f"{'IDX':<5} {'FILE PATH':<65}")
    print("-" * 70)
    
    for idx, file in enumerate(filtered_files, start=1):
        file_path = str(file)
        print(f"{idx:<5} {file_path:<65}")
    
    print("="*70)
    
    # Get user selection
    print("\n🔍 Select files to scan:")
    print("   - Enter indices separated by commas (e.g., 1,3,5)")
    print("   - Enter 'all' to scan all files")
    print("   - Enter 'q' to cancel")
    
    selection = input("\nYour selection: ").strip()
    
    if selection.lower() in ['q', 'quit', 'cancel']:
        print("❌ Cancelled")
        return
    
    # Parse selection
    selected_files = []
    
    if selection.lower() == 'all':
        selected_files = [str(f) for f in filtered_files]
        print(f"\n✅ Selected all {len(selected_files)} files")
    else:
        try:
            indices = [int(x.strip()) for x in selection.split(',') if x.strip()]
            selected_files = [
                str(filtered_files[i-1]) 
                for i in indices 
                if 1 <= i <= len(filtered_files)
            ]
            
            if not selected_files:
                print("❌ No valid files selected")
                return
            
            print(f"\n✅ Selected {len(selected_files)} file(s):")
            for f in selected_files:
                print(f"   - {f}")
                
        except (ValueError, IndexError) as e:
            print(f"❌ Invalid selection: {e}")
            return
    
    # Confirm and scan
    confirm = input(f"\n🔒 Scan these {len(selected_files)} file(s)? (y/n): ").strip().lower()
    
    if confirm not in ['y', 'yes']:
        print("❌ Cancelled")
        return
    
    # Initialize RAG system
    pipeline.setup_rag_system()
    
    # Run scanning on ONLY selected files
    print(f"\n🚀 Starting scan of {len(selected_files)} file(s)...")
    
    results = pod_analyzer.run_pod_pipeline(yaml_files=selected_files)
    
    display_scan_results(results, selected_files)


def handle_cluster_resource_scan(pipeline, pod_analyzer):
    """Handle scanning resources from Kubernetes cluster"""
    print("\n🔄 Connecting to Kubernetes cluster...")
    
    # List all resources from cluster
    resources = pod_analyzer.list_k8s_resources(all_namespaces=True)
    
    if not resources:
        print("\n❌ No resources found in cluster")
        print("   Make sure:")
        print("   - Minikube/cluster is running")
        print("   - kubectl is configured correctly")
        print("   - You have access to the cluster")
        return
    
    # Display resources
    pod_analyzer.pretty_print_resources(resources, "Kubernetes Cluster Resources")
    
    # Get user selection
    print("\n🔍 Select resources to scan:")
    print("   - Enter indices separated by commas (e.g., 1,3,5)")
    print("   - Enter 'all' to scan all resources")
    print("   - Enter 'q' to cancel")
    
    selection = input("\nYour selection: ").strip()
    
    if selection.lower() in ['q', 'quit', 'cancel']:
        print("❌ Cancelled")
        return
    
    # Parse selection
    selected_resources = []
    
    if selection.lower() == 'all':
        selected_resources = resources
        print(f"\n✅ Selected all {len(selected_resources)} resources")
    else:
        try:
            indices = [int(x.strip()) for x in selection.split(',') if x.strip()]
            selected_resources = [
                resources[i-1] 
                for i in indices 
                if 1 <= i <= len(resources)
            ]
            
            if not selected_resources:
                print("❌ No valid resources selected")
                return
            
            print(f"\n✅ Selected {len(selected_resources)} resource(s):")
            for r in selected_resources:
                print(f"   - {r['kind']}/{r['name']} (namespace: {r['namespace']})")
                
        except (ValueError, IndexError) as e:
            print(f"❌ Invalid selection: {e}")
            return
    
    # Confirm and scan
    confirm = input(f"\n🔒 Extract & scan these {len(selected_resources)} resource(s)? (y/n): ").strip().lower()
    
    if confirm not in ['y', 'yes']:
        print("❌ Cancelled")
        return
    
    # Initialize RAG system
    pipeline.setup_rag_system()
    
    # Run pipeline in cluster extraction mode
    print(f"\n🚀 Extracting & scanning {len(selected_resources)} resource(s) from cluster...")
    
    results = pod_analyzer.run_pod_pipeline(
        from_cluster=True,
        resource_selections=selected_resources
    )
    
    # Build file list for display (these are temp extracted files)
    extracted_files = []
    if results.get('scan_results'):
        extracted_files = list(results['scan_results'].keys())
    
    display_scan_results(results, extracted_files, from_cluster=True)


def handle_manual_manifest_input(pipeline, pod_analyzer):
    """Handle manual manifest path input"""
    print("\n📝 Manual manifest input")
    print("Enter manifest paths separated by commas:")
    
    manifest_input = input("Paths: ").strip()
    
    if not manifest_input:
        print("❌ No manifests specified")
        return
    
    manifest_files = [p.strip() for p in manifest_input.split(',') if p.strip()]
    
    # Validate files exist
    valid_manifests = []
    for m in manifest_files:
        if Path(m).exists():
            valid_manifests.append(m)
            print(f"✅ Found: {m}")
        else:
            print(f"⚠️ File not found: {m}")
    
    if not valid_manifests:
        print("❌ No valid manifest files found")
        return
    
    confirm = input(f"\n🔒 Scan these {len(valid_manifests)} file(s)? (y/n): ").strip().lower()
    
    if confirm not in ['y', 'yes']:
        print("❌ Cancelled")
        return
    
    # Initialize RAG system
    pipeline.setup_rag_system()
    
    print(f"\n🚀 Starting scan of {len(valid_manifests)} file(s)...")
    
    results = pod_analyzer.run_pod_pipeline(yaml_files=valid_manifests)
    
    display_scan_results(results, valid_manifests)


def display_scan_results(results, selected_files, from_cluster=False):
    """Display scan results summary"""
    if 'error' in results:
        print(f"\n❌ Error: {results['error']}")
        return
    
    print("\n" + "="*70)
    print("✅ SCAN COMPLETE")
    print("="*70)
    
    print(f"\n📊 Summary:")
    print(f"   Files scanned: {results['files_analyzed']}")
    print(f"   Issues found: {results['total_issues']}")
    
    if from_cluster:
        print(f"   Source: Kubernetes cluster (extracted manifests)")
    else:
        print(f"   Source: Local YAML files")
    
    # Show breakdown by file
    if results.get('scan_results'):
        print(f"\n📋 Issues by file:")
        for yaml_file in selected_files:
            if yaml_file in results['scan_results']:
                scan_data = results['scan_results'][yaml_file]
                filename = Path(yaml_file).name
                issues = scan_data.get('issues', 0)
                status_icon = "✅" if issues == 0 else "⚠️"
                print(f"   {status_icon} {filename}: {issues} issues")
    
    # Show scan output files
    print(f"\n📂 Scan output files saved in: {Path('outputs/scans/kubernetes_scans').absolute()}")
    
    if results.get('scan_outputs'):
        for yaml_file, outputs in results['scan_outputs'].items():
            filename = Path(yaml_file).name
            print(f"\n   {filename}:")
            if outputs.get('kubescore_file'):
                print(f"      - kube-score: {Path(outputs['kubescore_file']).name}")
            if outputs.get('kubescape_file'):
                print(f"      - kubescape: {Path(outputs['kubescape_file']).name}")
            if outputs.get('kyverno_file'):
                print(f"      - kyverno: {Path(outputs['kyverno_file']).name}")
    
    # Show improved manifests
    if results.get('improved_manifests'):
        print(f"\n🔒 Improved manifests: {len(results['improved_manifests'])}")
        print(f"   Saved in: {Path('outputs/safer_manifests').absolute()}")
        for original, improved in results['improved_manifests'].items():
            print(f"   {Path(original).name} → {Path(improved).name}")
    else:
        print(f"\n✅ No critical security issues requiring manifest regeneration")
    
    # Show report
    print(f"\n📄 Full report: {results['report_file']}")
    
    print("="*70)
    
    # Open report option
    open_report = input("\n📖 Open report file? (y/n): ").strip().lower()
    if open_report in ['y', 'yes']:
        try:
            import os
            report_path = Path(results['report_file']).absolute()
            
            if sys.platform == 'win32':
                os.startfile(str(report_path))
            elif sys.platform == 'darwin':
                os.system(f'open "{report_path}"')
            else:
                os.system(f'xdg-open "{report_path}"')
            
            print(f"✅ Opening: {report_path}")
        except Exception as e:
            print(f"⚠️ Could not open report: {e}")
            print(f"   Please open manually: {results['report_file']}")


def handle_chatbot(pipeline):
    """Start security chatbot"""
    print("\n" + "="*70)
    print("🤖 SECURITY ASSISTANT")
    print("="*70)
    pipeline.setup_rag_system()
    chatbot = SecurityChatbot(pipeline)
    chatbot.run()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Universal Container Security Pipeline - Image, Pod, and Chatbot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (recommended)
  python security_pipeline_main.py --interactive
  
  # Image security analysis
  python security_pipeline_main.py --image myapp:latest
  
  # Pod security analysis (local files)
  python security_pipeline_main.py --manifests deploy.yaml service.yaml
  
  # Pod security analysis (from cluster)
  python security_pipeline_main.py --cluster
  
  # Chatbot only
  python security_pipeline_main.py --chatbot
        """
    )
    
    parser.add_argument("--image", "-i", help="Container image name to scan")
    parser.add_argument("--manifests", "-m", nargs="+", help="Kubernetes manifest files to scan")
    parser.add_argument("--cluster", action="store_true", 
                       help="Extract and scan resources from Kubernetes cluster")
    parser.add_argument("--interactive", "-int", action="store_true", 
                       help="Run in interactive mode (default)")
    parser.add_argument("--chatbot", "-c", action="store_true", 
                       help="Start chatbot directly")
    
    args = parser.parse_args()
    
    # Setup pipeline
    pipeline = setup_pipeline()
    
    # Chatbot mode
    if args.chatbot:
        handle_chatbot(pipeline)
        return
    
    # Interactive mode (default)
    if args.interactive or (not args.image and not args.manifests and not args.cluster):
        interactive_menu(pipeline)
        return
    
    # Direct image scanning mode
    if args.image:
        print("🐳 Image scanning mode")
        pipeline.setup_rag_system()
        
        image_analyzer = ImageSecurityAnalyzer(pipeline)
        
        try:
            results = image_analyzer.run_image_pipeline(args.image)
            
            print("\n" + "="*70)
            print("✅ IMAGE ANALYSIS COMPLETE")
            print("="*70)
            print(f"\n📊 Summary:")
            print(f"   Total vulnerabilities: {results['total_vulnerabilities']}")
            print(f"   Fixable vulnerabilities: {results['fixable_vulnerabilities']}")
            print(f"   Report: {results['report_file']}")
            
            if results.get('dockerfile_path'):
                print(f"   Secured Dockerfile: {results['dockerfile_path']}")
            
            print("="*70)
            
        except Exception as e:
            print(f"\n❌ Error: {e}")
            logging.error(f"Image pipeline failed: {e}", exc_info=True)
        
        return
    
    # Direct cluster scanning mode
    if args.cluster:
        print("☸️ Cluster scanning mode")
        pipeline.setup_rag_system()
        pod_analyzer = PodSecurityAnalyzer(pipeline)
        handle_cluster_resource_scan(pipeline, pod_analyzer)
        return
    
    # Direct manifest scanning mode
    if args.manifests:
        print("☸️ Manifest scanning mode")
        
        # Validate files exist
        valid_manifests = []
        for m in args.manifests:
            if Path(m).exists():
                valid_manifests.append(m)
                print(f"✅ Found: {m}")
            else:
                print(f"⚠️ File not found: {m}")
        
        if not valid_manifests:
            print("❌ No valid manifest files found")
            return
        
        # Initialize RAG and scan
        pipeline.setup_rag_system()
        pod_analyzer = PodSecurityAnalyzer(pipeline)
        
        print(f"\n🚀 Starting scan of {len(valid_manifests)} file(s)...")
        
        results = pod_analyzer.run_pod_pipeline(yaml_files=valid_manifests)
        
        display_scan_results(results, valid_manifests)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ Pipeline interrupted by user. Goodbye! 👋")
    except Exception as e:
        logging.error(f"Pipeline failed: {e}", exc_info=True)
        sys.exit(1)