"""AXL SOAP body builders."""

from __future__ import annotations


def get_ccm_version_body() -> str:
    return "<axl:getCCMVersion />"


def list_process_node_body() -> str:
    return """<axl:listProcessNode>
      <searchCriteria>
        <name>%</name>
      </searchCriteria>
      <returnedTags>
        <name />
        <description />
        <nodeUsage />
      </returnedTags>
    </axl:listProcessNode>"""


def list_phone_body() -> str:
    return """<axl:listPhone>
      <searchCriteria>
        <name>%</name>
      </searchCriteria>
      <returnedTags>
        <name />
        <description />
        <model />
        <protocol />
        <devicePoolName />
        <locationName />
        <loadInformation />
      </returnedTags>
    </axl:listPhone>"""
