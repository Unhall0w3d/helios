"""Tests for assessment orchestration."""

from __future__ import annotations

import unittest

from cisco_collab_health.collectors.base import CollectionContext, TargetPipelineCollector
from cisco_collab_health.collectors.sample import SampleCollector
from cisco_collab_health.collectors.base import CollectionResult
from cisco_collab_health.engine import AssessmentEngine
from cisco_collab_health.rules.basic import (
    ClusterIdentityRule,
    CollectorHealthRule,
    NodeReachabilityRule,
)
from cisco_collab_health.models.facts import AssessmentFacts, CollaborationNode


class BrokenCollector:
    name = "broken"

    def collect(self, context: CollectionContext):
        del context
        raise RuntimeError("simulated collector failure")


class NodeCollector:
    name = "nodes"

    def collect(self, context: CollectionContext) -> CollectionResult:
        del context
        return CollectionResult(
            collector_name=self.name,
            facts=AssessmentFacts(
                nodes=[
                    CollaborationNode(
                        name="pub",
                        address="192.0.2.10",
                        role="publisher",
                    )
                ],
                devices=[],
            ),
        )


class ContextRecordingCollector:
    name = "recording"

    def __init__(self) -> None:
        self.discovered_nodes: tuple[str, ...] = ()
        self.discovered_device_names: tuple[str, ...] = ()

    def collect(self, context: CollectionContext) -> CollectionResult:
        self.discovered_nodes = context.discovered_nodes
        self.discovered_device_names = context.discovered_device_names
        return CollectionResult(collector_name=self.name, facts=AssessmentFacts())


class AssessmentEngineTests(unittest.TestCase):
    def test_target_pipeline_keeps_discovery_inside_target_context(self) -> None:
        recorder = ContextRecordingCollector()
        pipeline = TargetPipelineCollector(
            target_id="call-control",
            technology="cucm",
            collectors=(NodeCollector(), recorder),
            target_context=CollectionContext(
                product="cucm",
                publisher_ip="192.0.2.10",
                gui_username="cucm-admin",
            ),
        )

        result = pipeline.collect(CollectionContext(product="multi"))

        self.assertEqual(result.collector_name, "call-control[cucm]")
        self.assertEqual(recorder.discovered_nodes, ("192.0.2.10",))
        self.assertEqual(len(result.facts.nodes), 1)
        self.assertEqual(result.facts.nodes[0].technology, "cucm")
        self.assertEqual(result.facts.nodes[0].target_id, "call-control")

    def test_sample_assessment_runs_end_to_end(self) -> None:
        engine = AssessmentEngine(
            collectors=[SampleCollector()],
            rules=[ClusterIdentityRule(), NodeReachabilityRule()],
        )

        report = engine.run()

        self.assertIsNotNone(report.facts.cluster)
        self.assertEqual(len(report.facts.nodes), 2)
        self.assertEqual(len(report.collector_results), 1)
        self.assertEqual(
            [finding.rule_id for finding in report.findings],
            ["core.cluster_identity", "core.node_reachability"],
        )

    def test_collector_exception_becomes_structured_error(self) -> None:
        engine = AssessmentEngine(
            collectors=[BrokenCollector(), SampleCollector()],
            rules=[ClusterIdentityRule(), NodeReachabilityRule()],
        )

        report = engine.run()

        self.assertEqual(len(report.collector_results), 2)
        self.assertEqual(report.collector_results[0].collector_name, "broken")
        self.assertEqual(len(report.collector_results[0].errors), 1)
        self.assertEqual(report.collector_results[0].errors[0].exception_type, "RuntimeError")
        self.assertEqual(
            report.collector_results[0].errors[0].message,
            "simulated collector failure",
        )
        self.assertEqual(len(report.facts.collector_issues), 1)
        self.assertEqual(report.facts.collector_issues[0].issue_type, "error")
        self.assertEqual(report.facts.cluster.name, "alpha-lab")

    def test_collector_health_rule_reports_collector_errors(self) -> None:
        engine = AssessmentEngine(
            collectors=[BrokenCollector(), SampleCollector()],
            rules=[CollectorHealthRule()],
        )

        report = engine.run()

        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].rule_id, "core.collector_health")
        self.assertIn("broken: error", report.findings[0].facts[0])

    def test_later_collectors_receive_nodes_discovered_earlier_in_the_run(self) -> None:
        recorder = ContextRecordingCollector()
        AssessmentEngine(collectors=[NodeCollector(), recorder], rules=[]).run()

        self.assertEqual(recorder.discovered_nodes, ("192.0.2.10",))
        self.assertEqual(recorder.discovered_device_names, ())


if __name__ == "__main__":
    unittest.main()
