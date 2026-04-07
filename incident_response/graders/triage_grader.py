"""
Triage-specific grader for incident response tasks.

Focuses on initial incident handling: acknowledgment, classification, and communication.
"""

from __future__ import annotations

from typing import Optional

from incident_response.graders.base import IncidentGrader
from incident_response.models import IncidentState, Severity


class TriageGrader(IncidentGrader):
    """
    Grader for triage tasks.

    Triage-specific weights (sum to 1.0):
    - classification: 0.40 - severity classification accuracy (doubled importance)
    - investigation: 0.20 - efficiency of investigation path
    - diagnosis: 0.00 - not needed for triage
    - remediation: 0.00 - not needed for triage
    - communication: 0.20 - quality of status updates
    - acknowledgment: 0.20 - whether incident was acknowledged
    """

    # Triage-specific weights
    WEIGHT_CLASSIFICATION: float = 0.40
    WEIGHT_INVESTIGATION: float = 0.20
    WEIGHT_DIAGNOSIS: float = 0.00
    WEIGHT_REMEDIATION: float = 0.00
    WEIGHT_COMMUNICATION: float = 0.20
    WEIGHT_ACKNOWLEDGMENT: float = 0.20

    def score_acknowledgment(self, acknowledged: bool) -> float:
        """
        Score whether the incident was acknowledged.

        Args:
            acknowledged: Whether the agent acknowledged the incident.

        Returns:
            0.2 if acknowledged, 0.0 if not.
        """
        return 0.2 if acknowledged else 0.0

    def compute_final_score(self, state: IncidentState) -> dict[str, float]:
        """
        Compute the final score breakdown for triage tasks.

        Overrides base to use triage-specific weights and add acknowledgment scoring.

        Args:
            state: The current incident state containing all tracking info.

        Returns:
            Dictionary with score breakdown including:
            - classification, investigation, acknowledgment, communication
            - time_penalty, wrong_action_penalty
            - total (clamped to [0.0, 1.0])
        """
        # Score each component
        classification_score = self.score_classification(
            state.severity_classified,
            self.ground_truth_severity,
        )

        investigation_score = self.score_investigation(
            state.investigation_steps,
            state.wasted_steps,
            state.useful_investigations,
        )

        acknowledgment_score = self.score_acknowledgment(state.acknowledged)

        # Score communication - check the last status update
        last_message = state.status_updates[-1] if state.status_updates else None
        communication_score = self.score_communication(
            last_message,
            self.affected_services,
            state.severity_classified,
        )

        # Calculate time penalty
        time_penalty = self.TIME_PENALTY_PER_STEP * state.step_count

        # Calculate wrong action penalty based on wasted steps
        wrong_action_penalty = min(
            state.wasted_steps * self.WRONG_ACTION_PENALTY_MIN,
            self.WRONG_ACTION_PENALTY_MAX * 2,
        )

        # Weight the scores according to triage weights
        # classification max is 0.2, we want weight 0.40, so multiply by 2.0
        weighted_classification = classification_score * (self.WEIGHT_CLASSIFICATION / 0.2)
        # investigation max is 0.2, we want weight 0.20, so multiply by 1.0
        weighted_investigation = investigation_score * (self.WEIGHT_INVESTIGATION / 0.2)
        # acknowledgment max is 0.2, we want weight 0.20, so multiply by 1.0
        weighted_acknowledgment = acknowledgment_score * (self.WEIGHT_ACKNOWLEDGMENT / 0.2)
        # communication max is 0.1, we want weight 0.20, so multiply by 2.0
        weighted_communication = communication_score * (self.WEIGHT_COMMUNICATION / 0.1)

        # Sum weighted scores
        raw_total = (
            weighted_classification
            + weighted_investigation
            + weighted_acknowledgment
            + weighted_communication
            - time_penalty
            - wrong_action_penalty
        )

        # Clamp ALL scores to (0.0, 1.0) - strictly between, not inclusive
        def clamp(v: float) -> float:
            return max(0.001, min(0.999, v))

        return {
            "classification": clamp(classification_score),
            "investigation": clamp(investigation_score),
            "diagnosis": clamp(0.0),  # Not applicable for triage
            "remediation": clamp(0.0),  # Not applicable for triage
            "acknowledgment": clamp(acknowledgment_score),
            "communication": clamp(communication_score),
            "time_penalty": clamp(time_penalty),
            "wrong_action_penalty": clamp(wrong_action_penalty),
            "total": clamp(raw_total),
        }
