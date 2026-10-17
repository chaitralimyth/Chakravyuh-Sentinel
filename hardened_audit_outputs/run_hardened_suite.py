"""
Master Runner for Post-Hardening Empirical Audit Suite
Executes Phase 2 (Classification), Phase 3 (Decision Policy),
Phase 4 (Enforcement Verification), and Phase 5 (Performance Benchmarks).
Outputs all artifacts to hardened_audit_outputs/
"""

import os
import sys
import subprocess
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def run_step(step_name, script_filename):
    print(f"\n{'='*70}")
    print(f"[RUNNER] Starting {step_name}: {script_filename}")
    print(f"{'='*70}")
    script_path = os.path.join(SCRIPT_DIR, script_filename)
    t0 = time.time()
    result = subprocess.run([sys.executable, script_path], cwd=SCRIPT_DIR, capture_output=True, text=True)
    elapsed = time.time() - t0

    print(result.stdout)
    if result.stderr:
        print("[STDERR / WARNINGS]:")
        print(result.stderr)

    if result.returncode != 0:
        print(f"[ERROR] {step_name} failed with return code {result.returncode}")
        sys.exit(result.returncode)

    print(f"[RUNNER] Completed {step_name} in {elapsed:.2f}s (PASS)")

def main():
    print("======================================================================")
    print("  Chakravyuh Sentinel — Post-Hardening Empirical Audit Suite Runner")
    print("======================================================================")

    # Step 1: Classification Audit
    run_step("Phase 2: Classification Audit", "run_classification_audit.py")

    # Step 2: Policy Thresholds and Boundary Tests
    run_step("Phase 3: Decision Policy Tests", "test_decision_policy_audit.py")

    # Step 3: Enforcement & Middleware Verification
    run_step("Phase 4: Enforcement Verification", "test_enforcement_audit.py")

    # Step 4: High-Precision Performance Benchmarking
    run_step("Phase 5: Performance Benchmarking", "run_performance_benchmark.py")

    print("\n======================================================================")
    print("  ALL POST-HARDENING AUDIT PHASES EXECUTED SUCCESSFULLY (100% PASS)")
    print("======================================================================")

if __name__ == "__main__":
    main()
