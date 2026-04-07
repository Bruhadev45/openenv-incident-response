"""
Root Cause Analysis (RCA) specific grader for incident response tasks.

Focuses on accurate diagnosis with bonuses for efficient investigation.
"""

from __future__ import annotations

from typing import Optional

from incident_response.graders.base import IncidentGrader
from incident_response.models import IncidentState, Severity


class RCAGrader(IncidentGrader):
    """
    Grader for root cause analysis tasks.

    RCA-specific weights (sum to 1.0):
    - classification: 0.10 - severity classification accuracy
    - investigation: 0.25 - efficiency of investigation path (increased)
    - diagnosis: 0.40 - root cause identification accuracy (primary focus)
    - remediation: 0.15 - correct fix applied to correct service
    - communication: 0.10 - quality of status updates
    """

    # RCA-specific weights
    WEIGHT_CLASSIFICATION: float = 0.10
    WEIGHT_INVESTIGATION: float = 0.25
    WEIGHT_DIAGNOSIS: float = 0.40
    WEIGHT_REMEDIATION: float = 0.15
    WEIGHT_COMMUNICATION: float = 0.10

    # Bonus thresholds for fast diagnosis
    FAST_DIAGNOSIS_THRESHOLD: int = 3  # Steps to qualify for bonus
    FAST_DIAGNOSIS_BONUS: float = 0.05  # Bonus for fast diagnosis

    def compute_fast_diagnosis_bonus(self, steps: int, root_cause_correct: bool) -> float:
        """
        Calculate bonus for identifying root cause quickly.

        Args:
            steps: Number of investigation steps taken.
            root_cause_correct: Whether the root cause was correctly identified.

        Returns:
            Bonus score (0.0 to 0.05) for fast and correct diagnosis.
        """
        if not root_cause_correct:
            return 0.0

        if steps <= self.FAST_DIAGNOSIS_THRESHOLD:
            # Full bonus for very fast diagnosis
            return self.FAST_DIAGNOSIS_BONUS
        elif steps <= self.FAST_DIAGNOSIS_THRESHOLD + 2:
            # Partial bonus for moderately fast diagnosis
            return self.FAST_DIAGNOSIS_BONUS * 0.5
        else:
            return 0.0

    def compute_final_score(self, state: IncidentState) -> dict[str, float]:
        """
        Compute the final score breakdown for RCA tasks.

        Overrides base to use RCA-specific weights and add fast diagnosis bonus.

        Args:
            state: The current incident state containing all tracking info.

        Returns:
            Dictionary with score breakdown including:
            - classification, investigation, diagnosis, remediation, communication
            - fast_diagnosis_bonus
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

        # Extract category from root cause if possible
        root_cause_parts = self.ground_truth_root_cause.split("_")
        category = root_cause_parts[0] if root_cause_parts else None

        diagnosis_score = self.score_diagnosis(
            state.root_cause_identified,
            self.ground_truth_root_cause,
            self.ground_truth_primary_service,
            expected_category=category,
            expected_symptoms=None,
        )

        # Score remediation - check the last applied remediation
        last_remediation = state.remediations_applied[-1] if state.remediations_applied else None
        remediation_score = self.score_remediation(
            last_remediation,
            self.ground_truth_primary_service,
            self.ground_truth_remediations,
            self.ground_truth_primary_service,
        )

        # Score communication - check the last status update
        last_message = state.status_updates[-1] if state.status_updates else None
        communication_score = self.score_communication(
            last_message,
            self.affected_services,
            state.severity_classified,
        )

        # Calculate fast diagnosis bonus
        fast_diagnosis_bonus = self.compute_fast_diagnosis_bonus(
            state.investigation_steps,
            state.root_cause_correct,
        )

        # Calculate time penalty
        time_penalty = self.TIME_PENALTY_PER_STEP * state.step_count

        # Calculate wrong action penalty based on wasted steps
        wrong_action_penalty = min(
            state.wasted_steps * self.WRONG_ACTION_PENALTY_MIN,
            self.WRONG_ACTION_PENALTY_MAX * 2,
        )

        # Weight the scores according to RCA weights
        # classification max is 0.2, we want weight 0.10, so multiply by 0.5
        weighted_classification = classification_score * (self.WEIGHT_CLASSIFICATION / 0.2)
        # investigation max is 0.2, we want weight 0.25, so multiply by 1.25
        weighted_investigation = investigation_score * (self.WEIGHT_INVESTIGATION / 0.2)
        # diagnosis max is 0.3, we want weight 0.40, so multiply by ~1.33
        weighted_diagnosis = diagnosis_score * (self.WEIGHT_DIAGNOSIS / 0.3)
        # remediation max is 0.2, we want weight 0.15, so multiply by 0.75
        weighted_remediation = remediation_score * (self.WEIGHT_REMEDIATION / 0.2)
        # communication max is 0.1, we want weight 0.10, so multiply by 1.0
        weighted_communication = communication_score * (self.WEIGHT_COMMUNICATION / 0.1)

        # Sum weighted scores
        raw_total = (
            weighted_classification
            + weighted_investigation
            + weighted_diagnosis
            + weighted_remediation
            + weighted_communication
            + fast_diagnosis_bonus
            - time_penalty
            - wrong_action_penalty
        )

        # Clamp to [0.0, 1.0]
        total = max(0.001, min(0.999, raw_total))

        return {
            "classification": classification_score,
            "investigation": investigation_score,
            "diagnosis": diagnosis_score,
            "remediation": remediation_score,
            "communication": communication_score,
            "fast_diagnosis_bonus": fast_diagnosis_bonus,
            "time_penalty": time_penalty,
            "wrong_action_penalty": wrong_action_penalty,
            "total": total,
        }
