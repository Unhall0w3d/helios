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


def list_phone_body(*, first: int | None = None, skip: int | None = None) -> str:
    paging_attributes = _paging_attributes(first=first, skip=skip)
    return f"""<axl:listPhone{paging_attributes}>
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


def list_device_defaults_body() -> str:
    return """<axl:listDeviceDefaults>
      <searchCriteria>
        <model>%</model>
      </searchCriteria>
      <returnedTags>
        <model />
        <protocol />
        <loadInformation />
      </returnedTags>
    </axl:listDeviceDefaults>"""


def _paging_attributes(*, first: int | None, skip: int | None) -> str:
    attributes = []
    if first is not None:
        attributes.append(f'first="{first}"')
    if skip is not None:
        attributes.append(f'skip="{skip}"')
    if not attributes:
        return ""
    return " " + " ".join(attributes)
