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


DEVICE_DEFAULTS_SQL = """select count(d.tkmodel) as configuredcount,
tp.name as modelname, df.tkdeviceprotocol as signalingprotocol,
df.loadinformation as devicedefault, d.tkmodel as tkmodel
from device as d
inner join typeproduct as tp on d.tkmodel=tp.tkmodel
inner join defaults as df on tp.tkmodel=df.tkmodel
where df.loadinformation != ""
group by d.tkmodel, tp.name, df.loadinformation, df.tkdeviceprotocol"""


def execute_sql_query_body(sql: str) -> str:
    """Build an AXL executeSQLQuery request with XML-safe SQL text."""

    return f"<axl:executeSQLQuery><sql>{escape(sql)}</sql></axl:executeSQLQuery>"


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
