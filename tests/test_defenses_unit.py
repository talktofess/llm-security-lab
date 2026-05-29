"""Each exploit is blocked by its single primary control, in isolation —
showing the controls are independent (and the strongest are model-independent).
"""
import pytest

from seclab.agent.agent import Agent
from seclab.config import AgentConfig, Defenses
from seclab.exploits import ALL_EXPLOITS, PRIMARY_DEFENSE


@pytest.mark.parametrize("exploit", ALL_EXPLOITS, ids=lambda e: e.id)
def test_primary_defense_blocks_in_isolation(exploit):
    defense_field = PRIMARY_DEFENSE[exploit.attack_class]
    only_one = Defenses(**{defense_field: True})
    agent = Agent(AgentConfig(defenses=only_one))
    assert not exploit.run(agent).succeeded, (
        f"{defense_field} alone should block {exploit.id}"
    )


@pytest.mark.parametrize("exploit", ALL_EXPLOITS, ids=lambda e: e.id)
def test_all_defenses_off_lets_exploit_land(exploit):
    agent = Agent(AgentConfig(defenses=Defenses()))  # all off == vulnerable
    assert exploit.run(agent).succeeded
