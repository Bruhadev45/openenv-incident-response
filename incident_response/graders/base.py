"""
Base grader class for scoring agent performance on incident response tasks.

Provides deterministic scoring across multiple dimensions of incident handling.
"""

from __future__ import annotations

from typing import Optional

from incident_response.models import IncidentState, Severity


class IncidentGrader:
    """
    Base grader for incident response tasks.

    Scoring components (weights sum to 1.0):
    - classification: 0.20 - severity classification accuracy
    - investigation: 0.20 - efficiency of investigation path
    - diagnosis: 0.30 - root cause identification accuracy
    - remediation: 0.20 - correct fix applied to correct service
    - communication: 0.10 - quality of status updates

    Also tracks:
    - time_penalty: -0.01 per step
    - wrong_action_penalty: -0.05 to -0.2 for harmful actions
    """

    # Default weights (sum to 1.0)
    WEIGHT_CLASSIFICATION: float = 0.20
    WEIGHT_INVESTIGATION: float = 0.20
    WEIGHT_DIAGNOSIS: float = 0.30
    WEIGHT_REMEDIATION: float = 0.20
    WEIGHT_COMMUNICATION: float = 0.10

    # Penalties
    TIME_PENALTY_PER_STEP: float = 0.01
    WRONG_ACTION_PENALTY_MIN: float = 0.05
    WRONG_ACTION_PENALTY_MAX: float = 0.20

    # Severity ordering for one-off calculation
    SEVERITY_ORDER: list[Severity] = [Severity.P1, Severity.P2, Severity.P3, Severity.P4]

    def __init__(
        self,
        ground_truth_root_cause: str,
        ground_truth_severity: Severity,
        ground_truth_remediations: list[str],
        ground_truth_primary_service: str,
        affected_services: list[str],
    ) -> None:
        """
        Initialize the grader with ground truth values.

        Args:
            ground_truth_root_cause: The actual root cause identifier.
            ground_truth_severity: The correct severity classification.
            ground_truth_remediations: List of correct remediation actions.
            ground_truth_primary_service: The primary affected service.
            affected_services: All services affected by the incident.
        """
        self.ground_truth_root_cause = ground_truth_root_cause
        self.ground_truth_severity = ground_truth_severity
        self.ground_truth_remediations = ground_truth_remediations
        self.ground_truth_primary_service = ground_truth_primary_service
        self.affected_services = affected_services

    def score_classification(
        self,
        classified_severity: Optional[Severity],
        expected_severity: Severity,
    ) -> float:
        """
        Score severity classification accuracy.

        Args:
            classified_severity: The severity the agent classified.
            expected_severity: The ground truth severity.

        Returns:
            0.2 for exact match, 0.1 for one-off, 0.0 otherwise.
        """
        if classified_severity is None:
            return 0.0

        if classified_severity == expected_severity:
            return 0.2

        # Check for one-off (adjacent severity levels)
        try:
            classified_idx = self.SEVERITY_ORDER.index(classified_severity)
            expected_idx = self.SEVERITY_ORDER.index(expected_severity)
            if abs(classified_idx - expected_idx) == 1:
                return 0.1
        except ValueError:
            pass

        return 0.0

    def score_investigation(
        self,
        steps: int,
        wasted: int,
        useful_tools: list[str],
    ) -> float:
        """
        Score investigation efficiency.

        Optimal investigation takes 2-3 steps with no wasted steps.

        Args:
            steps: Total investigation steps taken.
            wasted: Number of wasted (unhelpful) investigation steps.
            useful_tools: List of useful tools that were used.

        Returns:
            Score from 0.0 to 0.2 based on efficiency.
        """
        if steps == 0:
            # No investigation performed
            return 0.0

        # Base score for completing any investigation
        base_score = 0.2

        # Optimal range is 2-3 steps
        optimal_min = 2
        optimal_max = 3

        if optimal_min <= steps <= optimal_max and wasted == 0:
            # Perfect investigation
            return base_score

        # Penalize for inefficiency
        efficiency_penalty = 0.0

        # Too few steps might mean incomplete investigation
        if steps < optimal_min:
            efficiency_penalty += 0.05 * (optimal_min - steps)

        # Too many steps reduces score
        if steps > optimal_max:
            excess_steps = steps - optimal_max
            efficiency_penalty += 0.02 * excess_steps

        # Wasted steps penalty
        efficiency_penalty += 0.03 * wasted

        # Bonus for using diverse useful tools
        tool_bonus = min(0.02 * len(useful_tools), 0.06)

        score = base_score - efficiency_penalty + tool_bonus
        return max(0.0, min(score, 0.2))

    def score_diagnosis(
        self,
        diagnosis: Optional[str],
        expected_root_cause_id: str,
        expected_service: str,
        expected_category: Optional[str] = None,
        expected_symptoms: Optional[list[str]] = None,
    ) -> float:
        """
        Score root cause identification accuracy.

        Args:
            diagnosis: The root cause the agent identified.
            expected_root_cause_id: The ground truth root cause identifier.
            expected_service: The expected primary service.
            expected_category: Optional category of the root cause.
            expected_symptoms: Optional list of expected symptoms.

        Returns:
            0.3 for exact match, 0.2 for service match, 0.15 for category match,
            0.1 for symptom match, 0.0 otherwise.
        """
        if diagnosis is None:
            return 0.0

        diagnosis_lower = diagnosis.lower()
        expected_root_cause_lower = expected_root_cause_id.lower()

        # Exact root cause match
        if expected_root_cause_lower in diagnosis_lower or diagnosis_lower == expected_root_cause_lower:
            return 0.3

        # Check for root cause ID match (handles cases like "memory_leak" matching "memory-leak")
        normalized_diagnosis = diagnosis_lower.replace("-", "_").replace(" ", "_")
        normalized_expected = expected_root_cause_lower.replace("-", "_").replace(" ", "_")
        if normalized_diagnosis == normalized_expected or normalized_expected in normalized_diagnosis:
            return 0.3

        # Service match (correctly identified the service, wrong root cause)
        expected_service_lower = expected_service.lower()
        if expected_service_lower in diagnosis_lower:
            return 0.2

        # Category match (e.g., "memory issue" when root cause is "memory_leak")
        if expected_category:
            expected_category_lower = expected_category.lower()
            if expected_category_lower in diagnosis_lower:
                return 0.15

        # Symptom match (mentioned relevant symptoms)
        if expected_symptoms:
            for symptom in expected_symptoms:
                if symptom.lower() in diagnosis_lower:
                    return 0.1

        return 0.0

    def score_remediation(
        self,
        remediation: Optional[str],
        target: Optional[str],
        expected_remediations: list[str],
        expected_target: str,
    ) -> float:
        """
        Score remediation action correctness.

        Args:
            remediation: The remediation action the agent applied.
            target: The target service the agent applied it to.
            expected_remediations: List of correct remediation actions.
            expected_target: The expected target service.

        Returns:
            0.2 for correct action on correct target, 0.1 for correct action only,
            -0.1 for wrong/harmful action.
        """
        if remediation is None:
            return 0.0

        remediation_lower = remediation.lower()
        target_lower = (target or "").lower()
        expected_target_lower = expected_target.lower()

        # Check if remediation is in expected list
        remediation_correct = any(
            expected.lower() == remediation_lower or expected.lower() in remediation_lower
            for expected in expected_remediations
        )

        # Check if target is correct
        target_correct = (
            target_lower == expected_target_lower
            or expected_target_lower in target_lower
            or target_lower in expected_target_lower
        )

        if remediation_correct and target_correct:
            return 0.2
        elif remediation_correct:
            return 0.1
        else:
            # Wrong remediation action is harmful
            return -0.1

    def score_communication(
        self,
        message: Optional[str],
        affected_services: list[str],
        severity: Optional[Severity],
    ) -> float:
        """
        Score quality of status update communication.

        Evaluates whether the message mentions affected services and conveys
        appropriate urgency for the severity level.

        Args:
            message: The status update message.
            affected_services: List of affected services.
            severity: The incident severity.

        Returns:
            Score from 0.0 to 0.1 based on communication quality.
        """
        if not message:
            return 0.0

        message_lower = message.lower()
        score = 0.0

        # Check if message mentions affected services (up to 0.04)
        services_mentioned = sum(
            1 for service in affected_services if service.lower() in message_lower
        )
        if services_mentioned > 0:
            service_ratio = services_mentioned / len(affected_services) if affected_services else 0
            score += 0.04 * min(service_ratio, 1.0)

        # Check for appropriate urgency keywords (up to 0.03)
        urgency_keywords = {
            Severity.P1: ["critical", "outage", "down", "emergency", "immediate"],
            Severity.P2: ["major", "significant", "high", "urgent", "impacted"],
            Severity.P3: ["moderate", "partial", "degraded", "investigating"],
            Severity.P4: ["minor", "low", "cosmetic", "monitoring"],
        }

        if severity and severity in urgency_keywords:
            for keyword in urgency_keywords[severity]:
                if keyword in message_lower:
                    score += 0.03
                    break

        # Check for basic communication elements (up to 0.03)
        has_status = any(
            word in message_lower
            for word in ["investigating", "identified", "resolved", "monitoring", "working"]
        )
        has_impact = any(
            word in message_lower for word in ["impact", "affected", "users", "customers", "service"]
        )

        if has_status:
            score += 0.015
        if has_impact:
            score += 0.015

        return min(score, 0.1)

    def compute_final_score(self, state: IncidentState) -> dict[str, float]:
        """
        Compute the final score breakdown from the incident state.

        Args:
            state: The current incident state containing all tracking info.

        Returns:
            Dictionary with score breakdown including:
            - classification, investigation, diagnosis, remediation, communication
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

        # Extract category and symptoms from root cause if possible
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
            self.ground_truth_primary_service,  # Assume target from state
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

        # Calculate time penalty
        time_penalty = self.TIME_PENALTY_PER_STEP * state.step_count

        # Calculate wrong action penalty based on wasted steps
        wrong_action_penalty = min(
            state.wasted_steps * self.WRONG_ACTION_PENALTY_MIN,
            self.WRONG_ACTION_PENALTY_MAX * 2,
        )

        # Weight the scores
        weighted_classification = classification_score * (self.WEIGHT_CLASSIFICATION / 0.2)
        weighted_investigation = investigation_score * (self.WEIGHT_INVESTIGATION / 0.2)
        weighted_diagnosis = diagnosis_score * (self.WEIGHT_DIAGNOSIS / 0.3)
        weighted_remediation = remediation_score * (self.WEIGHT_REMEDIATION / 0.2)
        weighted_communication = communication_score * (self.WEIGHT_COMMUNICATION / 0.1)

        # Sum weighted scores
        raw_total = (
            weighted_classification
            + weighted_investigation
            + weighted_diagnosis
            + weighted_remediation
            + weighted_communication
            - time_penalty
            - wrong_action_penalty
        )

        # Clamp to (0.0, 1.0) - strictly between, not inclusive
        # Validator requires ALL scores > 0 and < 1
        def clamp(v: float) -> float:
            return max(0.001, min(0.999, v))

        return {
            "classification": clamp(classification_score),
            "investigation": clamp(investigation_score),
            "diagnosis": clamp(diagnosis_score),
            "remediation": clamp(remediation_score),
            "communication": clamp(communication_score),
            "time_penalty": clamp(time_penalty),
            "wrong_action_penalty": clamp(wrong_action_penalty),
            "total": clamp(raw_total),
        }
