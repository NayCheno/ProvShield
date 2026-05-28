#!/usr/bin/env python3
"""LLM-based paper reviewer for ProvShield.

Uses an LLM API to perform independent reviews of the paper draft,
simulating CCF-A security conference reviewer behavior.

Usage:
    python eval/scripts/llm_reviewer.py --paper paper/paper_draft.tex --rounds 2
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

try:
    from openai import OpenAI
except ImportError:
    print("Install openai: pip install openai")
    sys.exit(1)


REVIEW_PROMPT = """You are an expert reviewer for a top-tier security conference (CCS, USENIX Security, S&P, NDSS).
You are reviewing the following paper:

Title: ProvShield: Provenance-Typed Runtime Enforcement for MCP and Skill-Based LLM Agents

Please provide a detailed, critical review in the following format:

## Summary (2-3 sentences)
Brief summary of the paper's contribution.

## Strengths (3-5 bullet points)
What the paper does well.

## Weaknesses (3-5 bullet points)
What needs improvement. Be specific and constructive.

## Questions for Authors (2-3 questions)
Specific questions you would ask the authors.

## Missing Related Work
Any important related work that should be discussed.

## Technical Concerns
Any technical issues with the approach, formalization, or evaluation.

## Presentation Issues
Any writing, structure, or clarity issues.

## Overall Assessment
Recommendation: Strong Accept / Accept / Weak Accept / Weak Reject / Reject
Confidence: 4 (high) / 3 (medium) / 2 (low)
Score: 1-10

Be rigorous, fair, and specific. Point to specific sections, numbers, or claims when criticizing.
"""


def load_paper(path: str) -> str:
    """Load paper content."""
    p = Path(path)
    if p.suffix == ".tex":
        # Strip LaTeX commands for cleaner reading, keep structure
        text = p.read_text(encoding="utf-8")
        # Remove comments
        lines = [l for l in text.split("\n") if not l.strip().startswith("%")]
        return "\n".join(lines)
    return p.read_text(encoding="utf-8")


def review_paper(
    paper_text: str,
    base_url: str,
    api_key: str,
    model: str = "mimo-v2-pro",
    reviewer_id: int = 1,
) -> str:
    """Send paper to LLM for review."""
    client = OpenAI(base_url=base_url, api_key=api_key)

    # Truncate if too long (keep first ~60K chars for context window)
    if len(paper_text) > 60000:
        paper_text = paper_text[:60000] + "\n\n[Paper truncated for context window]"

    messages = [
        {"role": "system", "content": REVIEW_PROMPT},
        {"role": "user", "content": f"Here is the paper to review:\n\n{paper_text}"},
    ]

    print(f"  Reviewer {reviewer_id}: Sending paper ({len(paper_text)} chars) to {model}...")

    response = client.chat.completions.create(
        model=model,
        messages=messages,
        max_tokens=4000,
        temperature=0.7,
    )

    return response.choices[0].message.content


def main():
    parser = argparse.ArgumentParser(description="LLM Paper Reviewer")
    parser.add_argument("--paper", default="paper/paper_draft.tex", help="Paper path")
    parser.add_argument("--rounds", type=int, default=2, help="Number of independent reviews")
    parser.add_argument("--output", default="eval/results/llm_reviews.json", help="Output path")
    parser.add_argument("--model", default="mimo-v2-pro", help="Model to use")
    args = parser.parse_args()

    # Load API config from .env
    env_path = Path(__file__).resolve().parent.parent.parent / ".env"
    base_url = os.environ.get("OPENAI_BASE_URL", "")
    api_key = os.environ.get("OPENAI_API_KEY", "")

    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if ":" in line and not line.startswith("#"):
                key, _, value = line.partition(":")
                key = key.strip()
                value = value.strip()
                if key == "openai_base_url":
                    base_url = value
                elif key == "openai_api_key":
                    api_key = value

    if not base_url or not api_key:
        print("Error: Set OPENAI_BASE_URL and OPENAI_API_KEY in .env or environment")
        sys.exit(1)

    print(f"Paper: {args.paper}")
    print(f"Model: {args.model}")
    print(f"API: {base_url}")
    print(f"Rounds: {args.rounds}")

    paper_text = load_paper(args.paper)
    reviews = []

    for i in range(1, args.rounds + 1):
        print(f"\n--- Review {i}/{args.rounds} ---")
        try:
            review = review_paper(
                paper_text=paper_text,
                base_url=base_url,
                api_key=api_key,
                model=args.model,
                reviewer_id=i,
            )
            reviews.append({
                "reviewer_id": i,
                "model": args.model,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "review": review,
            })
            print(f"  Reviewer {i}: Complete ({len(review)} chars)")
            print(f"  Preview: {review[:200]}...")
        except Exception as e:
            print(f"  Reviewer {i}: Error - {e}")
            reviews.append({
                "reviewer_id": i,
                "model": args.model,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "error": str(e),
            })

        if i < args.rounds:
            print("  Waiting 2s between reviews...")
            time.sleep(2)

    # Save reviews
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(reviews, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nReviews saved to: {output_path}")


if __name__ == "__main__":
    main()
