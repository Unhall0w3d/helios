"""AXL SOAP body builders."""

from __future__ import annotations

from typing import TypeAlias
from xml.sax.saxutils import escape

TagTree: TypeAlias = dict[str, "TagTree"]


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


DEVICE_DEFAULTS_SQL = """select count(d.tkmodel) as configuredmodelcount,
tp.name as modelname, df.tkdeviceprotocol as signalingprotocol,
df.loadinformation as devicedefault, d.tkmodel as tkmodel
from device as d
inner join typeproduct as tp on d.tkmodel=tp.tkmodel
inner join defaults as df on tp.tkmodel=df.tkmodel
where df.loadinformation != ""
group by d.tkmodel, tp.name, df.loadinformation, df.tkdeviceprotocol"""


ROUTE_PATTERN_RELATIONSHIPS_SQL = """select first 500
n.pkid as routepatternuuid, n.dnorpattern as routepattern,
rp.name as partition, d.name as destination,
rl.selectionorder as selectionorder, rg.name as routegroup
from numplan as n
left join routepartition as rp on rp.pkid=n.fkroutepartition
inner join devicenumplanmap as dnpm on dnpm.fknumplan=n.pkid
inner join device as d on dnpm.fkdevice=d.pkid
left join routelist as rl on rl.fkdevice=d.pkid
left join routegroup as rg on rg.pkid=rl.fkroutegroup
where n.tkpatternusage=5
order by n.pkid, rl.selectionorder"""


LINE_GROUP_MEMBERS_SQL = """select first 500
lg.pkid as linegroupuuid, lg.name as linegroup,
n.dnorpattern as directorynumber, rp.name as partition,
lgmap.selectionorder as selectionorder
from linegroup as lg
inner join linegroupnumplanmap as lgmap on lgmap.fklinegroup=lg.pkid
inner join numplan as n on lgmap.fknumplan=n.pkid
left join routepartition as rp on rp.pkid=n.fkroutepartition
order by lg.pkid, lgmap.selectionorder"""


SIP_TRUNK_DESTINATIONS_SQL = """select first 500
d.pkid as trunkuuid, d.name as trunkname,
std.address as destination, std.port as destinationport
from device as d
inner join sipdevice as sd on sd.fkdevice=d.pkid
inner join siptrunkdestination as std on std.fksipdevice=sd.pkid
where d.tkmodel=131 and d.tkdeviceprotocol=11
order by d.pkid"""


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

    tags = _returned_tags_xml(returned_tags)
    return f"""<axl:{operation} first="{first}" skip="{skip}">
      <searchCriteria>
        <{criteria_tag}>%</{criteria_tag}>
      </searchCriteria>
      <returnedTags>
{tags}
      </returnedTags>
    </axl:{operation}>"""


def diagnostic_get_body(
    operation: str,
    *,
    key_fields: dict[str, str],
    returned_tags: tuple[str, ...],
) -> str:
    """Build a read-only AXL get request for a previously listed object."""

    keys = "\n".join(f"      <{tag}>{escape(value)}</{tag}>" for tag, value in key_fields.items())
    tags = _returned_tags_xml(returned_tags)
    return f"""<axl:{operation}>
{keys}
      <returnedTags>
{tags}
      </returnedTags>
    </axl:{operation}>"""


def _returned_tags_xml(paths: tuple[str, ...]) -> str:
    """Render one merged returnedTags tree instead of duplicate AXL containers."""

    tree: TagTree = {}
    for path in paths:
        branch = tree
        for part in path.split("/"):
            branch = branch.setdefault(part, {})

    def render(branch: TagTree) -> str:
        elements = []
        for tag, children in branch.items():
            if children:
                elements.append(f"<{tag}>{render(children)}</{tag}>")
            else:
                elements.append(f"<{tag} />")
        return "".join(elements)

    return "\n".join(f"        {render({tag: children})}" for tag, children in tree.items())


def _paging_attributes(*, first: int | None, skip: int | None) -> str:
    attributes = []
    if first is not None:
        attributes.append(f'first="{first}"')
    if skip is not None:
        attributes.append(f'skip="{skip}"')
    if not attributes:
        return ""
    return " " + " ".join(attributes)
