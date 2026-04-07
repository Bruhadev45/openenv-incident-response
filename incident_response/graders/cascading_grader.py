"""
Cascading failure specific grader for incident response tasks.

Focuses on correct remediation execution and proper ordering when fixing
cascading failures across multiple services.
"""

from __future__ import annotations

from typing import Optional

from incident_response.graders.base import IncidentGrader
from incident_response.models import IncidentState, Severity


class CascadingGrader(IncidentGrader):
    """
    Grader for cascading failure tasks.

    Cascading-specific weights (sum to 1.0):
    - classification: 0.10 - severity classification accuracy
    - investigation: 0.15 - efficiency of investigation path
    - diagnosis: 0.25 - root cause identification accuracy
    - remediation: 0.35 - correct fix applied to correct service (primary focus)
    - communication: 0.15 - quality of status updates

    Additional scoring:
    - remediation_order: Evaluates whether fixes were applied in the correct order
    """

    # Cascading-specific weights
    WEIGHT_CLASSIFICATION: float = 0.10
    WEIGHT_INVESTIGATION: float = 0.15
    WEIGHT_DIAGNOSIS: float = 0.25
    WEIGHT_REMEDIATION: float = 0.35
    WEIGHT_COMMUNICATION: float = 0.15

    def __init__(
        self,
        ground_truth_root_cause: str,
        ground_truth_severity: Severity,
        ground_truth_remediations: list[str],
        ground_truth_primary_service: str,
        affected_services: list[str],
        expected_remediation_order: Optional[list[str]] = None,
    ) -> None:
        """
        Initialize the cascading grader with ground truth values.

        Args:
            ground_truth_root_cause: The actual root cause identifier.
            ground_truth_severity: The correct severity classification.
            ground_truth_remediations: List of correct remediation actions.
            ground_truth_primary_service: The primary affected service.
            affected_services: All services affected by the incident.
            expected_remediation_order: The correct order of remediations.
        """
        super().__init__(
            ground_truth_root_cause,
            ground_truth_severity,
            ground_truth_remediations,
            ground_truth_primary_service,
            affected_services,
        )
        self.expected_remediation_order = expected_remediation_order or ground_truth_remediations

    def score_remediation_order(
        self,
        applied_remediations: list[str],
        expected_order: list[str],
    ) -> float:
        """
        Score whether remediations were applied in the correct order.

        For cascading failures, the order of fixes matters. Fixing upstream
        services before downstream ones can prevent additional damage.

        Args:
            applied_remediations: List of remediations applied by the agent.
            expected_order: The correct order of remediations.

        Returns:
            Full credit for correct order, partial credit for correct actions
            in wrong order, zero for missing critical actions.
        """
        if not applied_remediations:
            return 0.0

        if not expected_order:
            # No specific order required, just check if actions are correct
            return 0.15 if applied_remediations else 0.0

        # Normalize remediations for comparison
        applied_normalized = [r.lower() for r in applied_remediations]
        expected_normalized = [r.lower() for r in expected_order]

        # Check how many expected remediations were applied
        applied_set = set(applied_normalized)
        expected_set = set(expected_normalized)
        correct_actions = applied_set.intersection(expected_set)

        if not correct_actions:
            return 0.0

        # Calculate action coverage
        action_coverage = len(correct_actions) / len(expected_set) if expected_set else 0

        # Check if order is correct using longest common subsequence approach
        order_score = self._calculate_order_score(applied_normalized, expected_normalized)

        # Combine action coverage and order score
        # Weight: 60% for having correct actions, 40% for correct order
        combined_score = (0.6 * action_coverage + 0.4 * order_score) * 0.15

        return min(combined_score, 0.15)

    def _calculate_order_score(
        self,
        applied: list[str],
        expected: list[str],
    ) -> float:
        """
        Calculate how well the applied order matches the expected order.

        Uses longest common subsequence to determine order correctness.

        Args:
            applied: Applied remediations in order.
            expected: Expected remediations in order.

        Returns:
            Score from 0.0 to 1.0 indicating order correctness.
        """
        if not applied or not expected:
            return 0.0

        # Filter applied to only include expected remediations
        filtered_applied = [r for r in applied if r in expected]

        if not filtered_applied:
            return 0.0

        # Build position map for expected order
        expected_positions = {r: i for i, r in enumerate(expected)}

        # Check if filtered applied is in ascending order of expected positions
        positions = [expected_positions.get(r, -1) for r in filtered_applied if r in expected_positions]

        if not positions:
            return 0.0

        # Calculate longest increasing subsequence length
        lis_length = self._longest_increasing_subsequence_length(positions)

        # Score is ratio of LIS to total expected remediations
        return lis_length / len(expected)

    def _longest_increasing_subsequence_length(self, sequence: list[int]) -> int:
        """
        Calculate the length of the longest increasing subsequence.

        Args:
            sequence: List of integers.

        Returns:
            Length of longest increasing subsequence.
        """
        if not sequence:
            return 0

        # Dynamic programming approach
        n = len(sequence)
        dp = [1] * n

        for i in range(1, n):
            for j in range(i):
                if sequence[j] < sequence[i]:
                    dp[i] = max(dp[i], dp[j] + 1)

        return max(dp)

    def compute_final_score(self, state: IncidentState) -> dict[str, float]:
        """
        Compute the final score breakdown for cascading failure tasks.

        Overrides base to use cascading-specific weights and add order scoring.

        Args:
            state: The current incident state containing all tracking info.

        Returns:
            Dictionary with score breakdown including:
            - classification, investigation, diagnosis, remediation, communication
            - remediation_order
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

        # Score remediation order
        remediation_order_score = self.score_remediation_order(
            state.remediations_applied,
            self.expected_remediation_order,
        )

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

        # Weight the scores according to cascading weights
        # classification max is 0.2, we want weight 0.10, so multiply by 0.5
        weighted_classification = classification_score * (self.WEIGHT_CLASSIFICATION / 0.2)
        # investigation max is 0.2, we want weight 0.15, so multiply by 0.75
        weighted_investigation = investigation_score * (self.WEIGHT_INVESTIGATION / 0.2)
        # diagnosis max is 0.3, we want weight 0.25, so multiply by ~0.83
        weighted_diagnosis = diagnosis_score * (self.WEIGHT_DIAGNOSIS / 0.3)
        # remediation max is 0.2, we want weight 0.35, so multiply by 1.75
        weighted_remediation = remediation_score * (self.WEIGHT_REMEDIATION / 0.2)
        # communication max is 0.1, we want weight 0.15, so multiply by 1.5
        weighted_communication = communication_score * (self.WEIGHT_COMMUNICATION / 0.1)

        # Add remediation order score (already scaled to 0.15 max)
        # This is a bonus component that rewards proper sequencing
        weighted_order = remediation_order_score

        # Sum weighted scores
        raw_total = (
            weighted_classification
            + weighted_investigation
            + weighted_diagnosis
            + weighted_remediation
            + weighted_communication
            + weighted_order
            - time_penalty
            - wrong_action_penalty
        )

        # Clamp ALL scores to (0.0, 1.0) - strictly between, not inclusive
        def clamp(v: float) -> float:
            return max(0.001, min(0.999, v))

        return {
            "classification": clamp(classification_score),
            "investigation": clamp(investigation_score),
            "diagnosis": clamp(diagnosis_score),
            "remediation": clamp(remediation_score),
            "remediation_order": clamp(remediation_order_score),
            "communication": clamp(communication_score),
            "time_penalty": clamp(time_penalty),
            "wrong_action_penalty": clamp(wrong_action_penalty),
            "total": clamp(raw_total),
        }
