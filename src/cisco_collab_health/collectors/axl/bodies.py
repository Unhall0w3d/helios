"""AXL SOAP body builders."""

from __future__ import annotations

from xml.sax.saxutils import escape


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


def get_device_defaults_body(model: str, protocol: str) -> str:
    """Build a device-default lookup for one observed model/protocol pair."""

    return f"""<axl:getDeviceDefaults>
      <model>{escape(model)}</model>
      <protocol>{escape(protocol)}</protocol>
      <returnedTags>
        <model />
        <protocol />
        <loadInformation />
      </returnedTags>
    </axl:getDeviceDefaults>"""


def list_device_pool_body() -> str:
    return """<axl:listDevicePool>
      <searchCriteria>
        <name>%</name>
      </searchCriteria>
      <returnedTags>
        <name />
        <regionName />
        <locationName />
        <callManagerGroupName />
      </returnedTags>
    </axl:listDevicePool>"""


def diagnostic_list_body(
    operation: str,
    *,
    criteria_tag: str,
    returned_tags: tuple[str, ...],
    first: int,
    skip: int,
) -> str:
    """Build one bounded AXL list request from a trusted operation specification."""

    tags = "\n".join(f"        <{tag} />" for tag in returned_tags)
    return f"""<axl:{operation} first="{first}" skip="{skip}">
      <searchCriteria>
        <{criteria_tag}>%</{criteria_tag}>
      </searchCriteria>
      <returnedTags>
{tags}
      </returnedTags>
    </axl:{operation}>"""


def _paging_attributes(*, first: int | None, skip: int | None) -> str:
    attributes = []
    if first is not None:
        attributes.append(f'first="{first}"')
    if skip is not None:
        attributes.append(f'skip="{skip}"')
    if not attributes:
        return ""
    return " " + " ".join(attributes)
