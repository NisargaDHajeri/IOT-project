"""Agent legacy wrapper module."""
from agent.security_agent import run_agent_pipeline, SecurityAgentState


def analyze(context):
    return run_agent_pipeline(context)
