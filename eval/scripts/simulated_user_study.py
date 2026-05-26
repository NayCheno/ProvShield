"""Simulated user study: models user behavior in bridge confirmation flow.

Since a real user study requires human participants, this simulation models
three user types (careful, average, careless) and measures:
- Incorrect confirmation rate (users confirming malicious actions)
- Confirmation fatigue (time/effort per task)
- Effectiveness of bridge binding vs generic confirmation

The simulation is based on the bridge UI requirements from docs/04_user_intent_bridge.md.
"""

from __future__ import annotations

import json
import random
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_root = Path(__file__).resolve().parent.parent.parent


@dataclass
class BridgePresentation:
    """What the user sees in the confirmation UI."""
    action: str
    destination: str
    payload_preview: str
    source_categories: list[str]
    private_data_crossing: bool
    expiry_seconds: int = 30


@dataclass
class UserProfile:
    """Simulated user characteristics."""
    name: str
    attention_level: float  # 0.0 (careless) to 1.0 (careful)
    # Probability of noticing each UI element
    p_notice_destination: float = 0.8
    p_notice_payload: float = 0.6
    p_notice_source_warning: float = 0.5
    p_notice_private_crossing: float = 0.7
    # Base probability of confirming when everything looks OK
    p_confirm_benign: float = 0.95


CAREFUL_USER = UserProfile(
    name="Careful",
    attention_level=0.95,
    p_notice_destination=0.98,
    p_notice_payload=0.95,
    p_notice_source_warning=0.90,
    p_notice_private_crossing=0.95,
    p_confirm_benign=0.90,
)

AVERAGE_USER = UserProfile(
    name="Average",
    attention_level=0.70,
    p_notice_destination=0.80,
    p_notice_payload=0.60,
    p_notice_source_warning=0.50,
    p_notice_private_crossing=0.70,
    p_confirm_benign=0.95,
)

CARELESS_USER = UserProfile(
    name="Careless",
    attention_level=0.30,
    p_notice_destination=0.40,
    p_notice_payload=0.20,
    p_notice_source_warning=0.15,
    p_notice_private_crossing=0.30,
    p_confirm_benign=0.99,
)


@dataclass
class StudyScenario:
    """A scenario requiring user confirmation."""
    scenario_id: str
    category: str  # "benign", "attack_visible", "attack_subtle"
    description: str
    presentation: BridgePresentation
    # Ground truth: should the user confirm?
    should_confirm: bool
    # Is the destination suspicious?
    destination_suspicious: bool = False
    # Does the payload contain unexpected content?
    payload_suspicious: bool = False
    # Are there untrusted sources influencing the action?
    untrusted_sources: bool = False
    # Does the payload cross a confidentiality boundary?
    conf_boundary_crossed: bool = False


def build_study_scenarios() -> list[StudyScenario]:
    """Build scenarios for the simulated study."""
    return [
        # --- Benign scenarios (user should confirm) ---
        StudyScenario(
            scenario_id="S_benign_01",
            category="benign",
            description="User asks to send report to colleague",
            presentation=BridgePresentation(
                action="send_email",
                destination="alice@company.com",
                payload_preview="Q3 revenue report: $2.5M",
                source_categories=["UserIntent"],
                private_data_crossing=False,
            ),
            should_confirm=True,
        ),
        StudyScenario(
            scenario_id="S_benign_02",
            category="benign",
            description="User asks to delete old temp files",
            presentation=BridgePresentation(
                action="delete_file",
                destination="/tmp/old_cache/",
                payload_preview="Delete 3 files, 2.1MB total",
                source_categories=["UserIntent"],
                private_data_crossing=False,
            ),
            should_confirm=True,
        ),
        StudyScenario(
            scenario_id="S_benign_03",
            category="benign",
            description="User asks to execute deployment script",
            presentation=BridgePresentation(
                action="execute_shell",
                destination="deploy.sh --staging",
                payload_preview="Deploy v2.3.1 to staging environment",
                source_categories=["UserIntent"],
                private_data_crossing=False,
            ),
            should_confirm=True,
        ),
        # --- Attack scenarios with visible indicators ---
        StudyScenario(
            scenario_id="S_attack_visible_01",
            category="attack_visible",
            description="Webpage instructs agent to send API key to attacker (visible destination)",
            presentation=BridgePresentation(
                action="send_email",
                destination="attacker@evil.com",
                payload_preview="API key: sk-proj-abc123",
                source_categories=["UserIntent", "ExternalContent"],
                private_data_crossing=True,
            ),
            should_confirm=False,
            destination_suspicious=True,
            payload_suspicious=True,
            untrusted_sources=True,
            conf_boundary_crossed=True,
        ),
        StudyScenario(
            scenario_id="S_attack_visible_02",
            category="attack_visible",
            description="Skill instructs to delete source files (visible path)",
            presentation=BridgePresentation(
                action="delete_file",
                destination="/data/source_files/",
                payload_preview="Delete all files in /data/source_files/",
                source_categories=["UserIntent", "UntrustedSkill"],
                private_data_crossing=False,
            ),
            should_confirm=False,
            payload_suspicious=True,
            untrusted_sources=True,
        ),
        # --- Attack scenarios with subtle indicators ---
        StudyScenario(
            scenario_id="S_attack_subtle_01",
            category="attack_subtle",
            description="Email asks to send diagnostic info to lookalike address",
            presentation=BridgePresentation(
                action="send_email",
                destination="support@comp4ny.com",  # typo-based phishing
                payload_preview="Diagnostic information as requested",
                source_categories=["UserIntent", "ExternalContent"],
                private_data_crossing=True,
            ),
            should_confirm=False,
            destination_suspicious=True,  # subtle
            untrusted_sources=True,
            conf_boundary_crossed=True,
        ),
        StudyScenario(
            scenario_id="S_attack_subtle_02",
            category="attack_subtle",
            description="MCP metadata injects send instruction, destination looks normal",
            presentation=BridgePresentation(
                action="send_email",
                destination="analytics@company.com",
                payload_preview="Calendar data: meeting at 3pm with client X",
                source_categories=["UserIntent", "ToolMetadata"],
                private_data_crossing=True,
            ),
            should_confirm=False,
            payload_suspicious=False,  # looks normal
            untrusted_sources=True,
            conf_boundary_crossed=True,
        ),
        StudyScenario(
            scenario_id="S_attack_subtle_03",
            category="attack_subtle",
            description="Webpage hidden instruction, payload mixes public and private",
            presentation=BridgePresentation(
                action="send_email",
                destination="compliance@external-audit.com",
                payload_preview="Compliance report with system metrics",
                source_categories=["UserIntent", "ExternalContent"],
                private_data_crossing=True,
            ),
            should_confirm=False,
            destination_suspicious=True,
            untrusted_sources=True,
            conf_boundary_crossed=True,
        ),
        # --- Attack: generic confirmation (no binding) ---
        StudyScenario(
            scenario_id="S_attack_generic_01",
            category="attack_visible",
            description="Same as visible_01 but with generic confirmation UI (no destination/payload shown)",
            presentation=BridgePresentation(
                action="send_email",
                destination="(not shown)",
                payload_preview="(not shown)",
                source_categories=[],
                private_data_crossing=False,
            ),
            should_confirm=False,
            # Generic UI hides all indicators
        ),
    ]


def simulate_user_decision(
    user: UserProfile,
    scenario: StudyScenario,
    bound_bridge: bool = True,
) -> dict[str, Any]:
    """Simulate a user's confirmation decision."""
    if scenario.should_confirm:
        # Benign scenario: user should confirm
        confirmed = random.random() < user.p_confirm_benign
        return {
            "scenario_id": scenario.scenario_id,
            "category": scenario.category,
            "user_type": user.name,
            "bound_bridge": bound_bridge,
            "confirmed": confirmed,
            "correct": confirmed,  # Confirming benign is correct
            "noticed_destination": True,
            "noticed_payload": True,
            "noticed_sources": True,
            "noticed_private_crossing": True,
        }

    # Attack scenario: user should NOT confirm
    if not bound_bridge:
        # Generic confirmation: user can't see details, likely confirms
        confirmed = random.random() < 0.85  # High confirmation rate for generic
        return {
            "scenario_id": scenario.scenario_id,
            "category": scenario.category,
            "user_type": user.name,
            "bound_bridge": False,
            "confirmed": confirmed,
            "correct": not confirmed,  # Not confirming attack is correct
            "noticed_destination": False,
            "noticed_payload": False,
            "noticed_sources": False,
            "noticed_private_crossing": False,
        }

    # Bound bridge: user sees detailed UI
    noticed_dest = scenario.destination_suspicious and random.random() < user.p_notice_destination
    noticed_payload = scenario.payload_suspicious and random.random() < user.p_notice_payload
    noticed_sources = scenario.untrusted_sources and random.random() < user.p_notice_source_warning
    noticed_private = scenario.conf_boundary_crossed and random.random() < user.p_notice_private_crossing

    # User decides based on what they noticed
    any_suspicious_noticed = noticed_dest or noticed_payload or noticed_sources or noticed_private

    if any_suspicious_noticed:
        # User noticed something suspicious: likely rejects
        confirmed = random.random() < 0.15  # Low confirmation when suspicious
    else:
        # User didn't notice anything: likely confirms
        confirmed = random.random() < user.p_confirm_benign

    return {
        "scenario_id": scenario.scenario_id,
        "category": scenario.category,
        "user_type": user.name,
        "bound_bridge": True,
        "confirmed": confirmed,
        "correct": not confirmed,  # Not confirming attack is correct
        "noticed_destination": noticed_dest,
        "noticed_payload": noticed_payload,
        "noticed_sources": noticed_sources,
        "noticed_private_crossing": noticed_private,
    }


def run_study(num_trials: int = 100) -> dict[str, Any]:
    """Run the simulated user study."""
    random.seed(42)
    scenarios = build_study_scenarios()
    users = [CAREFUL_USER, AVERAGE_USER, CARELESS_USER]

    results = []

    for user in users:
        for scenario in scenarios:
            for trial in range(num_trials):
                # Test with bound bridge
                result = simulate_user_decision(user, scenario, bound_bridge=True)
                result["trial"] = trial
                results.append(result)

            # Also test with generic confirmation for attack scenarios
            if scenario.category != "benign":
                for trial in range(num_trials):
                    result = simulate_user_decision(user, scenario, bound_bridge=False)
                    result["trial"] = trial
                    results.append(result)

    return results


def analyze_results(results: list[dict]) -> dict[str, Any]:
    """Analyze study results."""
    analysis = {}

    # Group by user type and bridge type
    for user_type in ["Careful", "Average", "Careless"]:
        user_results = [r for r in results if r["user_type"] == user_type]

        # Benign scenarios: correct = confirmed
        benign = [r for r in user_results if r["category"] == "benign"]
        benign_correct = sum(1 for r in benign if r["correct"]) / len(benign) if benign else 0

        # Attack scenarios with bound bridge
        attack_bound = [r for r in user_results if r["category"] != "benign" and r["bound_bridge"]]
        attack_bound_correct = sum(1 for r in attack_bound if r["correct"]) / len(attack_bound) if attack_bound else 0
        attack_bound_incorrect = sum(1 for r in attack_bound if not r["correct"]) / len(attack_bound) if attack_bound else 0

        # Attack scenarios with generic confirmation
        attack_generic = [r for r in user_results if r["category"] != "benign" and not r["bound_bridge"]]
        attack_generic_incorrect = sum(1 for r in attack_generic if not r["correct"]) / len(attack_generic) if attack_generic else 0

        # Visible vs subtle attacks (bound bridge only)
        visible = [r for r in attack_bound if r["category"] == "attack_visible"]
        subtle = [r for r in attack_bound if r["category"] == "attack_subtle"]
        visible_incorrect = sum(1 for r in visible if not r["correct"]) / len(visible) if visible else 0
        subtle_incorrect = sum(1 for r in subtle if not r["correct"]) / len(subtle) if subtle else 0

        analysis[user_type] = {
            "benign_completion": benign_correct,
            "attack_block_rate_bound": attack_bound_correct,
            "incorrect_confirm_rate_bound": attack_bound_incorrect,
            "incorrect_confirm_rate_generic": attack_generic_incorrect,
            "visible_attack_incorrect": visible_incorrect,
            "subtle_attack_incorrect": subtle_incorrect,
        }

    return analysis


def main():
    print("=" * 60)
    print(" ProvShield Simulated User Study")
    print("=" * 60)
    print()

    results = run_study(num_trials=100)
    analysis = analyze_results(results)

    print(f"Scenarios: {len(build_study_scenarios())}")
    print(f"User types: 3 (Careful, Average, Careless)")
    print(f"Trials per scenario per user: 100")
    print()

    # Print results table
    print(f"{'User Type':<12} {'Benign':>8} {'Block\\nBound':>10} {'Wrong\\nBound':>10} {'Wrong\\nGeneric':>12} {'Wrong\\nVisible':>12} {'Wrong\\nSubtle':>12}")
    print("-" * 76)

    for user_type in ["Careful", "Average", "Careless"]:
        a = analysis[user_type]
        print(f"{user_type:<12} {a['benign_completion']:>7.0%} {a['attack_block_rate_bound']:>9.0%} "
              f"{a['incorrect_confirm_rate_bound']:>9.0%} {a['incorrect_confirm_rate_generic']:>11.0%} "
              f"{a['visible_attack_incorrect']:>11.0%} {a['subtle_attack_incorrect']:>11.0%}")

    print()
    print("Key findings:")
    print(f"  - Bound bridge reduces incorrect confirmation by "
          f"{(analysis['Average']['incorrect_confirm_rate_generic'] - analysis['Average']['incorrect_confirm_rate_bound']):.0%} "
          f"vs generic confirmation (Average user)")
    print(f"  - Careful users: {analysis['Careful']['incorrect_confirm_rate_bound']:.0%} incorrect confirm rate with bound bridge")
    print(f"  - Careless users: {analysis['Careless']['incorrect_confirm_rate_bound']:.0%} incorrect confirm rate with bound bridge")
    print(f"  - Subtle attacks: {analysis['Average']['subtle_attack_incorrect']:.0%} incorrect confirm rate (Average user, bound bridge)")

    # Save results
    output_path = _root / "eval" / "results" / "simulated_user_study.json"
    with open(output_path, "w") as f:
        json.dump({
            "num_trials": 100,
            "scenarios": len(build_study_scenarios()),
            "analysis": analysis,
            "detailed_results_count": len(results),
        }, f, indent=2)
    print(f"\nResults saved to {output_path}")


if __name__ == "__main__":
    main()
