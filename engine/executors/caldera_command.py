# rules/engine/executors/caldera_command.py
"""Generic CALDERA-agent ability executor (covers the psh/cmd use-cases)."""
from executors.registry import register
from result import make_result

@register("caldera_command")
def caldera_command(usecase, ctx):
    session = ctx.winrm_factory() if ctx.winrm_factory else None
    aid = ctx.caldera.create_ability(usecase)
    if not aid:
        return make_result(usecase, "SETUP_FAIL", False)
    return ctx.caldera.run_ability(aid, usecase, session)
